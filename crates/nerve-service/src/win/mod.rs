//! The Windows parts the node's and the center's services share: names and
//! SIDs ([`sid`]), the service control manager ([`scm`]), the protected DACL
//! of a service's folders ([`dacl`]), the Windows Event Log ([`event`]), a
//! pipe only some accounts may open ([`pipe`]), and the job object a command
//! runs in ([`job_object`], with its plain logic in [`job`]). Both services
//! are registered with the manager ([`service`]), run under its dispatcher
//! ([`dispatch`]), replace their program in `update` ([`update`]) and run a
//! program without the administrators' rights ([`restricted`]). The center
//! also asks who runs a process ([`process`]) and which process holds a
//! loopback connection ([`tcp`]). The machine's own
//! folders come from Windows, not from the environment ([`folders`]). What
//! is plain logic is compiled and tested on every platform.

pub mod dacl;
#[cfg(windows)]
pub mod dispatch;
#[cfg(windows)]
pub mod event;
pub mod folders;
pub mod job;
#[cfg(windows)]
pub mod job_object;
pub mod pipe;
#[cfg(windows)]
pub mod process;
pub mod procs;
#[cfg(windows)]
pub mod restricted;
#[cfg(windows)]
pub mod scm;
pub mod service;
#[cfg(windows)]
pub mod sid;
pub mod tcp;
pub mod update;
