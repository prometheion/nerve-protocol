//! The Windows parts the node's and the center's services share: names and
//! SIDs ([`sid`]), the service control manager ([`scm`]), the protected DACL
//! of a service's folders ([`dacl`]), the Windows Event Log ([`event`]), a
//! pipe only some accounts may open ([`pipe`]), and the job object a command
//! runs in ([`job_object`], with its plain logic in [`job`]). What is plain
//! logic is compiled and tested on every platform.

pub mod dacl;
#[cfg(windows)]
pub mod event;
pub mod job;
#[cfg(windows)]
pub mod job_object;
pub mod pipe;
#[cfg(windows)]
pub mod scm;
#[cfg(windows)]
pub mod sid;
