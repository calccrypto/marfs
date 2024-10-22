/*
Copyright (c) 2015, Los Alamos National Security, LLC
All rights reserved.

Copyright 2015.  Los Alamos National Security, LLC. This software was
produced under U.S. Government contract DE-AC52-06NA25396 for Los
Alamos National Laboratory (LANL), which is operated by Los Alamos
National Security, LLC for the U.S. Department of Energy. The
U.S. Government has rights to use, reproduce, and distribute this
software.  NEITHER THE GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY,
LLC MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY
FOR THE USE OF THIS SOFTWARE.  If software is modified to produce
derivative works, such modified software should be clearly marked, so
as not to confuse it with the version available from LANL.

Additionally, redistribution and use in source and binary forms, with
or without modification, are permitted provided that the following
conditions are met: 1. Redistributions of source code must retain the
above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
3. Neither the name of Los Alamos National Security, LLC, Los Alamos
National Laboratory, LANL, the U.S. Government, nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY LOS ALAMOS NATIONAL SECURITY, LLC AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL LOS
ALAMOS NATIONAL SECURITY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-----
NOTE:
-----
MarFS is released under the BSD license.

MarFS was reviewed and released by LANL under Los Alamos Computer Code
identifier: LA-CC-15-039.

MarFS uses libaws4c for Amazon S3 object communication. The original
version is at https://aws.amazon.com/code/Amazon-S3/2601 and under the
LGPL license.  LANL added functionality to the original work. The
original work plus LANL contributions is found at
https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/

use clap::Parser;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

// path components to leaves of marfs data tree
const PATH_SEGS: &[&str] = &[
    "pod",
    "block",
    "cap",
    "scat"
];

// use BTreeMap to remove duplicates and sort on keys
// do not manually allocate - use parse_user_thresholds
type Thresholds = BTreeMap::<u8, u64>;

/** Find directories matching <DAL root>/pod[0-9]+/block[0-9]+/cap[0-9]+/scat[0-9]+
 *
 * @param path       <DAL root> and lower
 * @param expected   the expected directory basename prefix
 * @param len        length of expected
 * @return list of paths that had the expected path segment pattern
 */
fn process_non_leaf(path: PathBuf, expected: &str, len: usize) -> Vec<PathBuf> {
    let mut found = vec![];

    let entries = match fs::read_dir(&path) {
        Ok(list)   => list,
        Err(error) => {
            println!("Warning: Could not read_dir {}: {}", path.display(), error);
            return found;
        },
    };

    // find paths that match current marfs path segment
    for entry_res in entries {
        let entry = match entry_res {
            Ok(entry)  => entry,
            Err(error) => {
                eprintln!("Warning: Could not get entry: {}", error);
                continue;
            },
        };

        let child = entry.path();

        if child.is_dir() == false {
            continue;
        }

        // make sure current basename has expected path segment
        if let Some(basename) = child.file_name() {               // Option <&OsStr>
            if len < basename.len() {
                if let Some(basename_str) = basename.to_str() {   // Option <&str>
                    if &basename_str[0..len] != expected {
                        continue;
                    }

                    if let Err(_) = &basename_str[len..].parse::<u32>() {
                        continue;
                    }

                    found.push(child);
                }
            }
        }
    }

    return found;
}

/** Select how old files are allowed to be given system
 * utilization and thresholds
 *
 * Example:
 *     thresholds:
 *         10 -> 60
 *         20 -> 1
 *
 * If the utilization is less than or equal to 10%, files older than
 * 60 seconds should be flushed. If the utilization is greater than
 * 10% and less than or equal to 20%, files older than 1 second should
 * be flushed.
 *
 * TODO: Change to BTreeMap::upper_bound once btree_cursors is merged.
 *
 * @param thresholds   mapping of thresholds to file age limits
 * @param utilization  system utilization
 * @return file age limit in seconds
 */
fn util2age(thresholds: &Thresholds, utilization: u8) -> u64 {
    // return the age associated with the first threshold
    // that is greater than or equal to the utilization
    for (threshold, age) in thresholds.iter() {
        if *threshold >= utilization {
            return *age;
        }
    }

    // this line does double duty as a compiler silencer
    // and as an invalid utilization value check
    panic!("Error: Utilization percentage not found");
}

/** Process files under <DAL root>/pod[0-9]+/block[0-9]+/cap[0-9]+/scat[0-9]+/
 *
 * @param path     <DAL root>/pod[0-9]+/block[0-9]+/cap[0-9]+/scat[0-9]+/
 * @param reftime  a timestamp to compare atimes with
 * @param age      if (reftime - file.atime) > age, print the file's path
 * @return number of files to flush (used for testing)
 */
fn process_leaf(path: PathBuf, reftime: Arc<SystemTime>, thresholds: Arc<Thresholds>) -> usize {
    let entries = match fs::read_dir(&path) {
        Ok(list)   => list,
        Err(error) => {
            eprintln!("Warning: Could not read_dir {}: {}", path.display(), error);
            return 0;
        },
    };

    // get the leaf's utilization
    let util = unsafe {
        use errno::errno;
        use libc;
        use std::ffi::CString;
        use std::mem;

        let path_cstr = CString::new(path.display().to_string()).unwrap();
        let mut vfs_st: libc::statvfs = mem::zeroed();

        if libc::statvfs(path_cstr.as_ptr(), &mut vfs_st as *mut libc::statvfs) < 0 {
            println!("Warning: Getting utilization for {} failed: {}", path.display(), errno());
            return 0;
        }

        (100 - vfs_st.f_bfree * 100 / vfs_st.f_blocks) as u8
    };

    // figure out the file age limit
    let age = util2age(&thresholds, util);

    let mut count = 0;

    // loop through leaf directory and find files older than the limit
    for entry_res in entries {
        let entry = match entry_res {
            Ok(entry)  => entry,
            Err(error) => {
                eprintln!("Warning: Could not get entry: {}", error);
                continue;
            },
        };

        if let Ok(entry_type) = entry.file_type() {
            let child = entry.path();
            if entry_type.is_file() {
                if let Ok(st) = child.metadata() {
                    if let Ok(atime) = st.accessed() {
                        if let Ok(dur) = reftime.duration_since(atime) {
                            // older than allowed file age - print path for flushing
                            if dur.as_secs() > age {
                                println!("{}", child.display());
                                count += 1;
                            }
                        }
                    }
                }
            }
            else {
                eprintln!("Warning: {} is not a file", child.display());
            }
        }
    }

    count
}

/** Recurse down to <DAL root>/pod[0-9]+/block[0-9]+/cap[0-9]+/scat[0-9]+
 * and find files that are older than the provided age
 *
 * @param dal_root <DAL root>
 * @param reftime  a timestamp to compare atimes with
 * @param age      if (reftime - file.atime) > age, print the file's path
 */
fn print_flushable_in_dal(dal_root: &PathBuf, reftime: &SystemTime, thresholds: &Thresholds) {
    use std::thread;

    // paths currently being processed
    let mut paths = vec![dal_root.clone()];

    for path_seg in PATH_SEGS {
        let mut next_level = vec![];
        let mut handles = vec![];

        // process directories in parallel
        for path in paths {
            let handle = thread::spawn(move || {
                process_non_leaf(path, path_seg, path_seg.len()) // thread takes ownership of current path
            });

            handles.push(handle);
        }

        // get children from threads
        for handle in handles {
            let children = handle.join().unwrap();
            next_level.extend(children);
        }

        // update paths to process for the next loop
        paths = next_level;
    }

    // process leaves
    let mut handles = vec![];
    for leaf in paths {
        let reftime_arc = Arc::new(*reftime);
        let thresholds_arc = Arc::new(thresholds.clone());

        let handle = thread::spawn(move || {
            let _ = process_leaf(leaf, reftime_arc, thresholds_arc);
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/** Convert <utilization>,<age> strings from the commandline
 * to integers and insert them into a map.
 *
 * Utilization is an integer representing utilization percentage.
 * An integer is required because rust does not have an Ord trait
 * defined for f32 and f64. https://stackoverflow.com/a/69117941/341683
 *
 * Age is integer number of seconds since Jan 1, 1970 00:00:00 UTC.
 *
 * Example:
 *
 *     <this program> ... <other args> ... 10,60 20,1
 *
 * @param args   a vector of strings parsed by clap
 * @param delim  separator between utilization and age
 * @return a mapping of utilizations to file age limits
 */
fn parse_user_thresholds(args: &Vec<String>, delim: char) -> Thresholds {
    let mut thresholds = Thresholds::from([
        (0, u64::MAX), // if utilization is at 0%, don't flush anything
        (100, 0),      // if utilization is at 100%, flush everything
    ]);

    for arg in args {
        match arg.split_once(delim) {
            Some((util_str, age_str)) => {
                let util = match util_str.parse::<u8>() {
                    Ok(val)    => val,
                    Err(error) => panic!("Error: Bad utilization string: '{}': {}", util_str, error),
                };

                if util > 100 {
                    panic!("Error: Utilization can be between 0% and 100%. Got '{}'", util);
                }

                let age = match age_str.parse::<u64>() {
                    Ok(val)    => val,
                    Err(error) => panic!("Error: Bad age string: '{}': {}", age_str, error),
                };

                thresholds.insert(util, age);
            },
            None => panic!("Error: Bad utilization,age string: '{}'", arg),
        }
    }

    thresholds
}

#[derive(Parser, Debug)]
#[command()]
struct Args {
    #[arg(help="DAL root path")]
    root: PathBuf,

    #[arg(help="Reference Timestamp (Seconds Since Epoch)")]
    reftime: u64,

    #[arg(help="Comma separated utilization percentage (integer) and age (integer seconds) thresholds")]
    thresholds: Vec<String>,
}

fn main() {
    let args = Args::parse();

    // get reference timestamp
    let reftime = SystemTime::UNIX_EPOCH + Duration::from_secs(args.reftime);

    // convert user input to a map
    let thresholds = parse_user_thresholds(&args.thresholds, ',');

    // find files older than age
    print_flushable_in_dal(&args.root, &reftime, &thresholds);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tempfile::{TempDir, tempdir};

    fn setup_dirs() -> (TempDir, PathBuf) {
        // DAL root
        let root = match tempdir() {
            Ok(path)   => path,
            Err(error) => panic!("Error: Could not create temporary directory: {}", error),
        };

        // create intermediate directories
        let mut path = PathBuf::from(root.path().to_path_buf().to_owned());

        for seg in PATH_SEGS {
            let numbered = PathBuf::from(String::new() + seg + "0");
            path = path.join(numbered);
            if let Err(error) = fs::create_dir(&path) {
                panic!("Error: Could not create path {}: {}", path.display(), error);
            }
        }

        // return root to prevent destructor call
        (root, path)
    }

    fn setup_file(path: &PathBuf, name: &str, atime: SystemTime) -> io::Result<()> {
        // create pod/block/cap/scat/*
        let mut filename = path.to_owned();
        filename = filename.join(name);

        let utime = fs::FileTimes::new().set_accessed(atime);

        let file = fs::File::create(&filename)?;
        file.set_times(utime)?;

        Ok(())
    }

    #[test]
    fn test_process_leaf() {
        let reftime = SystemTime::now();
        let (_root, path) = setup_dirs();

        // create 2 files
        let _ = setup_file(&path, "0", reftime - Duration::from_secs(1));
        let _ = setup_file(&path, "1", reftime - Duration::from_secs(24 * 60 * 60));

        // find files older than 2 seconds
        {
            let thresholds = Thresholds::from([(100, 2)]);
            assert_eq!(process_leaf(path.clone(), Arc::new(reftime), Arc::new(thresholds)), 1);
        }

        // find files older than 0 seconds
        {
            let thresholds = Thresholds::from([(100, 0)]);
            assert_eq!(process_leaf(path.clone(), Arc::new(reftime), Arc::new(thresholds)), 2);
        }
    }

    #[test]
    fn test_print_flushable_in_dal() {
        let (root, _) = setup_dirs();
        let thresholds = parse_user_thresholds(&vec!["0,2".to_string()], ',');
        print_flushable_in_dal(&root.path().to_path_buf(), &SystemTime::UNIX_EPOCH, &thresholds);
    }

    #[test]
    fn test_user_threshold_good_single() {
        let args = vec![
            "1,1".to_string(),
        ];

        let thresholds = parse_user_thresholds(&args, ',');
        assert_eq!(thresholds.len(), 3);
        assert_eq!(thresholds.get(&1), Some(&1));
    }

    #[test]
    fn test_user_threshold_good_multiple() {
        let args = vec![
            "1,1".to_string(),
            "2,2".to_string(),
        ];

        let thresholds = parse_user_thresholds(&args, ',');
        assert_eq!(thresholds.len(), 4);
        assert_eq!(thresholds.get(&1), Some(&1));
        assert_eq!(thresholds.get(&2), Some(&2));
    }

    #[test]
    fn test_user_threshold_good_repeat() {
        let args = vec![
            "0,0".to_string(),
        ];

        let thresholds = parse_user_thresholds(&args, ',');
        assert_eq!(thresholds.len(), 2);
        assert_eq!(thresholds.get(&0), Some(&0));
    }

    #[test]
    #[should_panic(expected = "Error: Bad utilization,age string: ''")]
    fn test_user_threshold_empty() {
        parse_user_thresholds(&vec!["".to_string()], ',');
    }

    #[test]
    #[should_panic(expected = "Error: Bad age string: '': cannot parse integer from empty string")]
    fn test_user_threshold_digit_empty() {
        parse_user_thresholds(&vec!["1,".to_string()], ',');
    }

    #[test]
    #[should_panic(expected = "Error: Bad utilization string: '': cannot parse integer from empty string")]
    fn test_user_threshold_empty_digit() {
        parse_user_thresholds(&vec![",1".to_string()], ',');
    }

    #[test]
    #[should_panic(expected = "Error: Bad utilization string: 'a': invalid digit found in string")]
    fn test_user_threshold_alpha_empty() {
        parse_user_thresholds(&vec!["a,".to_string()], ',');
    }

    #[test]
    #[should_panic(expected = "Error: Bad utilization string: '': cannot parse integer from empty string")]
    fn test_user_threshold_empty_alpha() {
        parse_user_thresholds(&vec![",a".to_string()], ',');
    }

    #[test]
    fn test_util2age() {
        // low  utilization -> flush older  files
        // high utilization -> flush recent files
        let args = vec![
            "10,90".to_string(),
            "20,80".to_string(),
            "30,70".to_string(),
            "40,60".to_string(),
            "50,50".to_string(),
            "60,40".to_string(),
            "70,30".to_string(),
            "80,20".to_string(),
            "90,10".to_string(),
        ];

        let thresholds = parse_user_thresholds(&args, ',');
        assert_eq!(thresholds.len(), 11);

        assert_eq!(util2age(&thresholds, 5),   90);
        assert_eq!(util2age(&thresholds, 15),  80);
        assert_eq!(util2age(&thresholds, 25),  70);
        assert_eq!(util2age(&thresholds, 35),  60);
        assert_eq!(util2age(&thresholds, 45),  50);
        assert_eq!(util2age(&thresholds, 55),  40);
        assert_eq!(util2age(&thresholds, 65),  30);
        assert_eq!(util2age(&thresholds, 75),  20);
        assert_eq!(util2age(&thresholds, 85),  10);
        assert_eq!(util2age(&thresholds, 95),  00);
    }

    #[test]
    fn test_util2age_empty() {
        let thresholds = parse_user_thresholds(&vec![], ',');
        assert_eq!(thresholds.len(), 2);
        util2age(&thresholds, 0);
    }

    #[test]
    #[should_panic(expected = "Error: Utilization percentage not found")]
    fn test_util2age_gt_100() {
        let thresholds = parse_user_thresholds(&vec![], ',');
        assert_eq!(thresholds.len(), 2);
        util2age(&thresholds, 200);
    }
}
