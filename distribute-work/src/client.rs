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
use tonic::{transport::Channel, Request};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::env;
use std::fs;
use std::path::PathBuf;
use tonic::metadata::MetadataValue;

use comms::WorkRequest;
use comms::distribute_work_client::DistributeWorkClient;
pub mod comms {
    tonic::include_proto!("comms");
}

#[derive(Parser, Debug)]
#[command()]
struct Cli {
    server: String,
    port: u16,

    #[arg(help="ssh private key file", long)]
    private_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let uri = format!("http://{}:{}", cli.server, cli.port).parse()?;
    println!("Connecting to {}", uri);

    // this process is running as uid = 1001 for job 0 and is rank 0
    let claims = alltoall::JWTClaims {
        user: 1001,
        job_id: 0,
        rank: 0,
    };

    // get path of ssh private key - can't use env::var("HOME") in default value
    // let pri_path = if let Some(pri) = cli.private_key {
    //     pri
    // } else {
    //     let mut path = PathBuf::from(env::var("HOME").unwrap());
    //     path.push(".ssh/id_rsa");
    //     path
    // };

    // https://serverfault.com/questions/706336/how-to-get-a-pem-file-from-ssh-key-pair
    // https://docs.mia-platform.eu/docs/runtime_suite/client-credentials/jwt_keys
    // ssh-keygen -t rsa -b 4096 -m PEM -f private.key
    // rm private.key.pub
    // ssh-keygen -f private.key -e -m PKCS8 > public.key

    let private_key = fs::read_to_string("private.key")?;
    // let pri_raw = fs::read_to_string(pri_path)?;
    let jwt = encode(&Header::new(Algorithm::HS256), &claims,
                     &EncodingKey::from_secret(private_key.as_bytes())
    )?;
    // let jwt = encode(&Header::new(Algorithm::RS256), &claims,
    //                  &EncodingKey::from_rsa_pem(pri_raw.as_bytes())?
    // )?;
    let token: MetadataValue<_> = jwt.parse()?;

    let channel = Channel::builder(uri)
        .connect()
        .await?;

    let mut client = DistributeWorkClient::with_interceptor(
        channel,
        move | mut req: Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    let request = tonic::Request::new(WorkRequest {});

    // call rpc
    let mut stream = client
        .get_work(request)
        .await?
        .into_inner();

    // process work
    while let Some(work) = stream.message().await? {
        println!("Got: {:?}", work);
    }

    Ok(())
}
