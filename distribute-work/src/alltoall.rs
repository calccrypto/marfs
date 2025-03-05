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



use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind};
use std::collections::LinkedList;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio::task;
use tokio::runtime::Runtime;
use tonic::metadata::MetadataValue;
use tonic::{transport, Request, Response, service, Status};
use futures::future;
use transport::Uri;

use comms::distribute_buffer_server::{DistributeBuffer, DistributeBufferServer};
use comms::distribute_buffer_client::DistributeBufferClient;
use comms::{BufferData, BufferReply};
pub mod comms {
    tonic::include_proto!("comms");
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub user: i32,
    pub job_id: i32,
    pub rank: i32,
}

#[derive(Default)]
pub struct MyDistributeBufferService {}

#[tonic::async_trait]
impl DistributeBuffer for MyDistributeBufferService {
    async fn send(&self, request: Request<BufferData>) -> Result<Response<BufferReply>, Status> {
        println!("Received buffer {:?}\n", request.into_inner().data);
        Ok(Response::new(BufferReply { status: 0 } ))
    }
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

#[derive(Clone)]
pub struct ServerInfo {
    uri: SocketAddr,
    secret: String,
}

impl ServerInfo {
    fn new(ipv6: bool, port: u16, sec: &String) -> Self {
        const IPV4: &str = "0.0.0.0";
        const IPV6: &str = "[::1]";

        let uri = format!("{0}:{1}", if ipv6 { IPV6 } else { IPV4 }, port).parse().unwrap();

        println!("Listening on {}", uri);

        ServerInfo {
            uri: uri,
            secret: sec.clone(),
        }
    }

    async fn start(&mut self) -> Result<(), transport::Error> {
        let ws = MyDistributeBufferService::default();
        let svc = DistributeBufferServer::with_interceptor(ws, self.clone());

        // start up server and yield

        // TODO: make sure the thread has started
        transport::Server::builder()
            .add_service(svc)
            .serve(self.uri)
            .await // TODO: change to serve_with_shutdown
    }
}

impl service::Interceptor for ServerInfo {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        println!("secret: {}", self.secret);

        // let token = req.metadata().get("authorization").unwrap().to_str().unwrap();

        // let mut validation = Validation::new(Algorithm::HS256);
        // validation.required_spec_claims.clear(); // remove needing exp

        // match decode::<claims::JWTClaims>(&token,
        //                                   &DecodingKey::from_secret(self.secret.as_bytes()),
        //                                   &validation) {
        //     Ok(_) => Ok(req),
        //     Err(err) => match *err.kind() {
        //         ErrorKind::InvalidToken => panic!("Token is invalid"),
        //         ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
        //         ErrorKind::InvalidSignature => panic!("Signature is invalid"),
        //         _ => panic!("{:?}", err),
        //     },
        // }
        Ok(req)
    }
}

#[derive(Clone)]
struct ClientState {
    uri: Uri,
}

impl ClientState {
    pub fn new(uri: &Uri) -> Self {
        ClientState {
            uri: uri.clone(),
        }
    }
}

pub struct Worker {
    secret:  String,
    work:    LinkedList<String>,
    jwt:     String,
    server:  ServerInfo,
    clients: LinkedList<ClientState>,
}

impl Worker {
    pub fn new(ipv6: bool, port: u16,
               secret: &String,
               // hosts: &Vec<SocketAddr>
    ) -> Worker {
        // TODO: Automatically fill in correctly
        let claims = JWTClaims {
            user: 1001,
            job_id: 0,
            rank: 0,
        };

        Worker {
            secret:   secret.clone(),
            work:     LinkedList::<String>::new(),
            jwt:      encode(&Header::new(Algorithm::HS256), &claims,
                             &EncodingKey::from_secret(secret.as_bytes())).unwrap(),
            server:   ServerInfo::new(ipv6, port, &secret.clone()),
            clients:  LinkedList::<ClientState>::new(),
        }
    }

    pub async fn start(&mut self, hosts: &Vec<SocketAddr>) -> task::JoinHandle<Result<(), transport::Error>> {
        let ret = task::spawn(self.server.start());

        let mut clients = Vec::<_>::new();

        println!("start");
        for host in hosts.iter() {
            let uri: Uri = format!("http://{}", host.to_string()).parse().unwrap();
            println!("    {uri}");
            let channel = transport::Channel::builder(uri.clone()).connect().await.unwrap();
            let token: MetadataValue<_> = self.jwt.parse().unwrap();

            // TODO: store this somewhere
            let dbc = DistributeBufferClient::with_interceptor(
                channel,
                move | mut req: Request<()>| {
                    req.metadata_mut().insert("authorization", token.clone());
                    Ok(req)
                });

            print_type_of(&dbc);
            clients.push(dbc.clone());

            self.clients.push_back(ClientState::new(&uri));
        }

        ret
    }

    // async fn new_sender(&mut self, uri: &SocketAddr) {
    //     let channel = transport::Channel::builder(uri.to_string().parse().unwrap()).connect().await?;
    //     let token: MetadataValue<_> = self.jwt.parse().unwrap();

    //     // TODO: store this somewhere
    //     let dbc = DistributeBufferClient::with_interceptor(
    //         channel,
    //         move | mut req: Request<()>| {
    //             req.metadata_mut().insert("authorization", token.clone());
    //             Ok(req)
    //         });

    //     print_type_of(&dbc);

    //     self.clients.push_back(ClientState::new(uri));

    //     dbc

    //     // let request = tonic::Request::new(BufferData{ data: "abc".as_bytes().to_vec() });

    //     // // call rpc
    //     // let reply = dbc
    //     //     .send(request)
    //     //     .await?
    //     //     .into_inner();

    //     // println!("reply: {:?}", reply);

    //     // // process work
    //     // while let Some(work) = stream.message().await? {
    //     //     println!("Got: {:?}", work);
    //     // }

    //     // Ok(())
    // }
}
