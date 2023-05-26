use std::net::{TcpListener, TcpStream};

use anyhow::Result;
use gdbstub::{
    conn::ConnectionExt,
    stub::{run_blocking, GdbStub, GdbStubError, SingleThreadStopReason},
    target::{
        ext::{
            base::{
                singlethread::{SingleThreadBase, SingleThreadRangeStepping, SingleThreadResume},
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

impl<'a> Target for GdbExecutor<'a> {
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

impl<'a> Breakpoints for GdbExecutor<'a> {
    fn support_sw_breakpoint(
        &mut self,
    ) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SwBreakpoint for GdbExecutor<'a> {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        eprintln!("setting breakpoint at {:X}", addr);
        self.breakpoints.push(addr);
        Ok(true)
    }
    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        match self.breakpoints.iter().position(|b| *b == addr) {
            None => Ok(false),
            Some(index) => {
                self.breakpoints.remove(index);
                return Ok(true);
            }
        }
    }
}

impl<'a> SingleThreadBase for GdbExecutor<'a> {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
    ) -> gdbstub::target::TargetResult<(), Self> {
        regs.x = self.exec.monitor.load_registers([
            REG_ZERO, REG_RA, REG_SP, REG_GP, REG_TP, REG_T0, REG_T1, REG_T2, REG_FP, REG_S1,
            REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5, REG_A6, REG_A7, REG_S2, REG_S3, REG_S4,
            REG_S5, REG_S6, REG_S7, REG_S8, REG_S9, REG_S10, REG_S11, REG_T3, REG_T4, REG_T5,
            REG_T6,
        ]);
        regs.pc = self.exec.pc;
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
    ) -> gdbstub::target::TargetResult<(), Self> {
        for i in 0..REG_MAX - 1 {
            self.exec.monitor.store_register(i, regs.x[i]);
        }
        self.exec.pc = regs.pc;
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &mut [u8],
    ) -> gdbstub::target::TargetResult<(), Self> {
        data.copy_from_slice(
            self.exec
                .monitor
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
        self.exec.monitor.store_region(start_addr as u32, data);
        Ok(())
    }

    #[inline(always)]
    fn support_resume(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SingleThreadResume for GdbExecutor<'a> {
    fn resume(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        Ok(())
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

pub enum GdbStatus {
    InComingData,
    Event(GdbEvent),
}

pub enum GdbEvent {
    DoneStep, // May want to collapse this in to DoneSteps(1)...
    DoneSteps(u32),
    ExecHalted(ExitCode),
    BreakpointHit,
}

pub struct GdbExecutor<'a> {
    exec: Executor<'a>,
    exec_state: ExecState,
    breakpoints: Vec<u32>,
}

pub enum ExecState {
    Step(u32),
    Continue,
}

impl<'a> GdbExecutor<'a> {
    pub fn init(env: ExecutorEnv<'a>, elf: &[u8]) -> Result<Self> {
        let mut exec = Executor::from_elf(env, elf)?;
        exec.init_executor_for_gdb();
        let connection: Box<dyn ConnectionExt<Error = std::io::Error>> =
            Box::new(wait_for_tcp(9000)?);
        let gdb = GdbStub::new(connection);
        let mut gdb_exec = Self {
            exec: exec,
            exec_state: ExecState::Continue,
            breakpoints: Vec::new(),
        };

        match gdb.run_blocking::<GdbExecutor<'a>>(&mut gdb_exec) {
            Ok(_) => println!("Target terminated!"),
            Err(GdbStubError::TargetError(e)) => {
                println!("target encountered a fatal error: {}", e)
            }
            Err(e) => {
                println!("gdbstub encountered a fatal error: {}", e)
            }
        }

        Ok(gdb_exec)
    }

    /// Run the executor until [ExitCode::Paused] or [ExitCode::Halted] is
    /// reached or a signal from gdb is called. This is intended to be called
    /// only during debugging in gdb and does not produce a [Session]
    pub fn run(
        &mut self,
        conn: &mut Box<dyn ConnectionExt<Error = std::io::Error>>,
    ) -> Result<GdbStatus> {
        match self.exec_state {
            ExecState::Continue => self.run_continue(conn),
            ExecState::Step(n) => self.run_n_steps(n),
        }
    }

    fn run_n_steps(&mut self, steps: u32) -> Result<GdbStatus> {
        for _ in 0..steps {
            if let GdbStatus::Event(GdbEvent::ExecHalted(h)) = self.step()? {
                return Ok(GdbStatus::Event(GdbEvent::ExecHalted(h)));
            }
        }
        return Ok(GdbStatus::Event(GdbEvent::DoneSteps(steps)));
    }

    fn step(&mut self) -> Result<GdbStatus> {
        use GdbEvent::*;
        use GdbStatus::*;
        match self.exec.step()? {
            Some(exit_code) => {
                log::debug!("exit_code: {exit_code:?}");
                match exit_code {
                    ExitCode::Paused(inner) => {
                        log::debug!("Paused({inner})");
                        return Ok(Event(ExecHalted(exit_code)));
                    }
                    ExitCode::Halted(inner) => {
                        log::debug!("Halted({inner})");
                        return Ok(Event(ExecHalted(exit_code)));
                    }
                    // ignore splits in gdb. This mode of execution is intended to focuse on
                    // stepping through the code
                    _ => return Ok(Event(DoneStep)),
                }
            }
            None => return Ok(Event(DoneStep)),
        }
    }

    fn run_continue(
        &mut self,
        conn: &mut Box<dyn ConnectionExt<Error = std::io::Error>>,
    ) -> Result<GdbStatus> {
        use GdbEvent::*;
        use GdbStatus::*;

        loop {
            if let Ok(Some(_)) = conn.peek() {
                return Ok(InComingData);
            }
            if self.breakpoints.contains(&self.exec.pc) {
                return Ok(Event(BreakpointHit));
            }
            if let Event(ExecHalted(h)) = self.step()? {
                return Ok(Event(ExecHalted(h)));
            }
        }
    }
}

impl<'a> run_blocking::BlockingEventLoop for GdbExecutor<'a> {
    type Target = GdbExecutor<'a>;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut GdbExecutor<'a>,
        conn: &mut Self::Connection,
    ) -> core::result::Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        match target.run(conn) {
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
                    GdbEvent::DoneSteps(_) => SingleThreadStopReason::DoneStep,
                    GdbEvent::BreakpointHit => SingleThreadStopReason::SwBreak(()),
                };
                Ok(run_blocking::Event::TargetStopped(stop_event))
            }
            Err(e) => Err(run_blocking::WaitForStopReasonError::Target(e)),
        }
    }

    fn on_interrupt(
        _target: &mut GdbExecutor<'a>,
    ) -> core::result::Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        todo!()
    }
}
