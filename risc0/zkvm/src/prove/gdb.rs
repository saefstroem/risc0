// Copyright 2022 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use anyhow::Error;
use gdbstub::arch::Arch;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target;
use gdbstub::target::ext::base::singlethread::SingleThreadBase;
use gdbstub::target::Target;
use gdbstub::target::TargetResult;
use gdbstub_arch;

use super::exec::HostHandler;
use super::exec::MachineContext;
use super::exec::RV32Executor;
use super::ProverImpl;

impl<'a, H: HostHandler> Target for RV32Executor<'a, H> {
    type Arch = gdbstub_arch::riscv::Riscv32;
    type Error = Error;

    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<Self::Arch, Self::Error> {
        target::ext::base::BaseOps::SingleThread(self)
    }
}

impl<'a, H: HostHandler> SingleThreadBase for RV32Executor<'a, H> {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        regs.pc = self.executor.handler.pc;
        for i in 0..32 {
            regs.x[i] = self.executor.handler.memory.load_register(i);
        }
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        for i in 0..32 {
            self.executor.handler.memory.store_register(i, regs.x[i]);
        }
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<(), Self> {
        let region_data = self
            .executor
            .handler
            .memory
            .load_region(start_addr, data.len() as u32);
        for i in 0..data.len() {
            data[i] = region_data[i];
        }
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        self.executor.handler.memory.store_region(start_addr, data);
        Ok(())
    }
}

enum GdbBlockingEventLoop {}

impl run_blocking::BlockingEventLoop for GdbBlockingEventLoop {
    type Target = RV32Executor<'static, ProverImpl<'static>>;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        todo!()
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        todo!()
    }
}
