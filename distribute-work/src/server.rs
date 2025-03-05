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



use clap::{ArgAction, Parser};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, errors::ErrorKind};
use std::collections::LinkedList;
use std::fs;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream};
use tonic::{transport::Server, Request, Response, Status};

use comms::distribute_work_server::{DistributeWork, DistributeWorkServer};
use comms::{WorkRequest, Work};
pub mod comms {
    tonic::include_proto!("comms");
}

#[derive(Default)]
pub struct MyDistributeWork {
    per_client_work_count: usize,       // floor(# of work items / clients)
    extra_work: usize,                  // the first n clients need to take an extra work item
    client: Mutex<usize>,               // current client id
    work_list: Mutex<LinkedList<Work>>,
}

#[tonic::async_trait]
impl DistributeWork for MyDistributeWork {
    type GetWorkStream = ReceiverStream<Result<Work, Status>>;

    async fn get_work(&self, request: Request<WorkRequest>) -> Result<Response<Self::GetWorkStream>, Status> {
        let mut id_lock = self.client.lock().unwrap();
        let id = *id_lock;
        *id_lock += 1;
        std::mem::drop(id_lock);

        let work_count = self.per_client_work_count + if id < self.extra_work { 1 } else { 0 };
        let mut client_work_items: LinkedList<Work> = LinkedList::new();

        for _ in 0..work_count {
            if let Some(w) = self.work_list.lock().unwrap().pop_front() {
                client_work_items.push_back(w);
            }
            else {
                break;
            }
        }

        println!("Client {:?} requesting work. Sending {} work items.",
                 request.remote_addr().unwrap(), client_work_items.len());

        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            for work in client_work_items {
                tx.send(Ok(work)).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

const IPV4: &str = "0.0.0.0";
const IPV6: &str = "[::1]";

#[derive(Parser, Debug)]
#[command()]
struct Cli {
    port: u16,

    #[arg(help="client count")]
    clients: usize,

    #[arg(help="Listen on IPv6 instead of IPv4", long, action=ArgAction::SetTrue)]
    ipv6: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let addr = format!("{0}:{1}", if cli.ipv6 { IPV6 } else { IPV4 }, cli.port).parse()?;

    // TODO: get work from somewhere
    let mut work_list = LinkedList::new();
    for i in 0..10 {
        work_list.push_back(Work {
            id: i,
            path: format!("/path{}", i),
        });
    }

    // server state
    let ws = MyDistributeWork{
        per_client_work_count: work_list.len() / cli.clients,
        extra_work: work_list.len() % cli.clients,
        client: Mutex::new(0),
        work_list: Mutex::new(work_list),
    };

    let svc = DistributeWorkServer::with_interceptor(ws, check_auth);

    println!("Listening on {:?}", addr);

    Server::builder()
        .add_service(svc)
        .serve(addr)
        .await?;

    Ok(())
}

fn check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    let token = req.metadata().get("authorization").unwrap().to_str().unwrap();
    let private_key = fs::read_to_string("private.key")?; // TODO: make this not hard-coded

    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear(); // remove needing exp

    match decode::<alltoall::JWTClaims>(&token,
                                        &DecodingKey::from_secret(private_key.as_bytes()),
                                        &validation) {
    // match decode::<alltoall::JWTClaims>(&token,
    //                                   &DecodingKey::from_rsa_pem(private_key.as_bytes()).unwrap(),
    //                                   &validation) {
        Ok(_) => Ok(req),
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"),
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
            ErrorKind::InvalidSignature => panic!("Signature is invalid"),
            _ => panic!("{:?}", err),
        },
    }
}
