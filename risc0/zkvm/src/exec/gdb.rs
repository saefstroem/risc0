use std::net::{TcpListener, TcpStream};

use anyhow::Result;
use gdbstub::{
    conn::ConnectionExt,
    stub::{run_blocking, GdbStub, SingleThreadStopReason},
    target::{
        ext::base::{
            singlethread::{SingleThreadBase, SingleThreadResume, SingleThreadSingleStep},
            BaseOps,
        },
        Target,
    },
};
use risc0_zkvm_platform::syscall::reg_abi::*;

use super::Executor;
use crate::{ExecutorEnv, MemoryImage, SyscallContext};

impl<'a> Target for Executor<'a> {
    type Error = anyhow::Error;
    type Arch = gdbstub_arch::riscv::Riscv32;

    fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
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
        todo!()
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl<'a> SingleThreadSingleStep for Executor<'a> {
    fn step(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
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

pub fn run_with_gdb<'a>(env: ExecutorEnv<'a>, elf: &[u8]) -> Result<Executor<'a>> {
    let mut exec = Executor::from_elf(env, elf)?;
    let connection: TcpStream = wait_for_tcp(9000)?;
    let gdb: GdbStub<'_, Executor, TcpStream> = GdbStub::new(connection);

    Ok(exec)
}

enum ExecutorGdbEventLoop {}

impl run_blocking::BlockingEventLoop for ExecutorGdbEventLoop {
    type Target = Executor;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> core::result::Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        // Give executor a polling function
    }
}
