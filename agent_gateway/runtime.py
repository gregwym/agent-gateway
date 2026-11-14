"""Drain in-flight MCP requests before atomically changing the active configuration."""
from contextlib import asynccontextmanager

import anyio


class Runtime:
    def __init__(self, gateway):
        self.gateway = gateway
        self.condition = anyio.Condition()
        self.active = 0
        self.changing = False
        self.tasks = None
        self.generation = None

    @staticmethod
    async def _generation(gateway, *, task_status=anyio.TASK_STATUS_IGNORED):
        async with anyio.create_task_group() as tasks:
            for upstream in gateway.upstreams.values():
                tasks.start_soon(upstream.run)
            task_status.started(tasks.cancel_scope)
            await anyio.sleep_forever()

    @asynccontextmanager
    async def run(self):
        async with anyio.create_task_group() as tasks:
            self.tasks = tasks
            self.generation = await tasks.start(self._generation, self.gateway)
            try:
                yield
            finally:
                tasks.cancel_scope.cancel()
                self.tasks = None

    @asynccontextmanager
    async def lease(self):
        async with self.condition:
            while self.changing:
                await self.condition.wait()
            self.active += 1
        try:
            yield self.gateway
        finally:
            with anyio.CancelScope(shield=True):
                async with self.condition:
                    self.active -= 1
                    self.condition.notify_all()

    async def replace(self, gateway, commit):
        # The caller serializes writers. Authentication is inside the lease, so a
        # token revoked by this change cannot sneak through after the publication.
        with anyio.CancelScope(shield=True):
            async with self.condition:
                self.changing = True
                try:
                    with anyio.fail_after(30):
                        while self.active:
                            await self.condition.wait()
                    commit()
                    old = self.generation
                    if self.tasks:
                        self.generation = await self.tasks.start(self._generation, gateway)
                    self.gateway = gateway
                    if old:
                        old.cancel()
                finally:
                    self.changing = False
                    self.condition.notify_all()
