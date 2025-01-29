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
use std::path::PathBuf;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

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

    #[arg(help="TLS Certificate Path", long, default_value="tls/server.pem")]
    cert: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let uri = format!("https://{}:{}", cli.server, cli.port).parse()?;
    println!("Connecting to {}", uri);

    let data_dir = std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
    let pem = std::fs::read_to_string(data_dir.join("tls/ca.pem"))?;
    let ca = Certificate::from_pem(pem);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("example.com");

    let channel = Channel::builder(uri)
        .tls_config(tls)?
        .connect()
        .await?;

    let mut client = DistributeWorkClient::new(channel);

    let request = tonic::Request::new(WorkRequest {});

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
