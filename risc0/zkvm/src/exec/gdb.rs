use std::net::{TcpListener, TcpStream};

use anyhow::Result;
use gdbstub::{
    conn::ConnectionExt,
    stub::{run_blocking, GdbStub, GdbStubError, SingleThreadStopReason},
    target::{
        ext::{
            base::{
                singlethread::{
                    SingleThreadBase, SingleThreadRangeStepping, SingleThreadResume,
                    SingleThreadSingleStep,
                },
                BaseOps,
            },
            breakpoints::{Breakpoints, SwBreakpoint},
        },
        Target,
    },
};
use risc0_zkvm_platform::syscall::reg_abi::*;

use super::Executor;
use crate::{ExecutorEnv, ExitCode, SyscallContext};

impl<'a> Target for Executor<'a> {
    type Error = anyhow::Error;
    type Arch = gdbstub_arch::riscv::Riscv32;

    fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_breakpoints(
        &mut self,
    ) -> Option<gdbstub::target::ext::breakpoints::BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> Breakpoints for Executor<'a> {
    fn support_sw_breakpoint(
        &mut self,
    ) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SwBreakpoint for Executor<'a> {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        todo!()
    }
    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        todo!()
    }
}

impl<'a> SingleThreadBase for Executor<'a> {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
    ) -> gdbstub::target::TargetResult<(), Self> {
        regs.x = self.monitor.load_registers([
            REG_ZERO, REG_RA, REG_SP, REG_GP, REG_TP, REG_T0, REG_T1, REG_T2, REG_FP, REG_S1,
            REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5, REG_A6, REG_A7, REG_S2, REG_S3, REG_S4,
            REG_S5, REG_S6, REG_S7, REG_S8, REG_S9, REG_S10, REG_S11, REG_T3, REG_T4, REG_T5,
            REG_T6,
        ]);
        regs.pc = self.pc;
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
    ) -> gdbstub::target::TargetResult<(), Self> {
        for i in 0..REG_MAX - 1 {
            self.monitor.store_register(i, regs.x[i]);
        }
        self.pc = regs.pc;
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &mut [u8],
    ) -> gdbstub::target::TargetResult<(), Self> {
        data.copy_from_slice(
            self.monitor
                .load_region(start_addr as u32, data.len() as u32)
                .as_mut_slice(),
        );
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &[u8],
    ) -> gdbstub::target::TargetResult<(), Self> {
        self.monitor.store_region(start_addr as u32, data);
        Ok(())
    }

    #[inline(always)]
    fn support_resume(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SingleThreadResume for Executor<'a> {
    fn resume(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline(always)]
    fn support_range_step(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::singlethread::SingleThreadRangeSteppingOps<'_, Self>>
    {
        Some(self)
    }
}
impl<'a> SingleThreadRangeStepping for Executor<'a> {
    fn resume_range_step(
        &mut self,
        start: <Self::Arch as gdbstub::arch::Arch>::Usize,
        end: <Self::Arch as gdbstub::arch::Arch>::Usize,
    ) -> core::result::Result<(), Self::Error> {
        todo!()
    }
}

fn wait_for_tcp(port: u16) -> Result<TcpStream> {
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn run_with_gdb<'a>(env: ExecutorEnv<'a>, elf: &[u8]) -> Result<()> {
    let mut exec = Executor::from_elf(env, elf)?;
    exec.init_executor_for_gdb();
    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(wait_for_tcp(9000)?);
    let gdb = GdbStub::new(connection);

    match gdb.run_blocking::<ExecutorGdbEventLoop<'a>>(&mut exec) {
        Ok(_) => println!("Target terminated!"),
        Err(GdbStubError::TargetError(e)) => {
            println!("target encountered a fatal error: {}", e)
        }
        Err(e) => {
            println!("gdbstub encountered a fatal error: {}", e)
        }
    }

    Ok(())
}

pub enum GdbStatus {
    InComingData,
    Event(GdbEvent),
}

pub enum GdbEvent {
    DoneStep,
    ExecHalted(ExitCode),
}

struct ExecutorGdbEventLoop<'a> {
    exec: Executor<'a>,
}

impl<'a> run_blocking::BlockingEventLoop for ExecutorGdbEventLoop<'a> {
    type Target = Executor<'a>;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut Executor<'a>,
        conn: &mut Self::Connection,
    ) -> core::result::Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        match target.run_with_gdb(conn) {
            Ok(GdbStatus::InComingData) => {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;
                Ok(run_blocking::Event::IncomingData(byte))
            }
            // TODO: how do we differentiate between halted and paused? Also need to send back
            // 32-bit status value
            Ok(GdbStatus::Event(event)) => {
                let stop_event = match event {
                    GdbEvent::ExecHalted(_) => SingleThreadStopReason::Exited(0),
                    GdbEvent::DoneStep => SingleThreadStopReason::DoneStep,
                };
                Ok(run_blocking::Event::TargetStopped(stop_event))
            }
            Err(e) => Err(run_blocking::WaitForStopReasonError::Target(e)),
        }
    }

    fn on_interrupt(
        _target: &mut Executor<'a>,
    ) -> core::result::Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        todo!()
    }
}
