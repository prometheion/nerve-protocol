//! The Windows parts the node's and the center's services share: names and
//! SIDs ([`sid`]), the service control manager ([`scm`]), the protected DACL
//! of a service's folders ([`dacl`]), the Windows Event Log ([`event`]), a
//! pipe only some accounts may open ([`pipe`]), and the job object a command
//! runs in ([`job_object`], with its plain logic in [`job`]). The center's
//! service also runs as a virtual account ([`service`]) under the manager's
//! dispatcher ([`dispatch`]), asks who runs a process ([`process`]), and
//! runs a program without the administrators' rights ([`restricted`]). What is plain logic
//! is compiled and tested on every platform.

pub mod dacl;
#[cfg(windows)]
pub mod dispatch;
#[cfg(windows)]
pub mod event;
pub mod job;
#[cfg(windows)]
pub mod job_object;
pub mod pipe;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod restricted;
#[cfg(windows)]
pub mod scm;
pub mod service;
#[cfg(windows)]
pub mod sid;
