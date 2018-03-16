#include "Ctu.h"

LogLevel g_LogLevel = Info;

Ctu::Ctu() : cpu(this), svc(this), ipc(this), tm(this), mmiohandler(this), bridge(this), gdbStub(this), handleId(0xde00), heapsize(0x0) {
	handles[0xffff8001] = make_shared<Process>(this);
}

void Ctu::execProgram(gptr ep) {
        auto sp = 0x3000000;
        auto ss = 0x1000000;

	cpu.map(sp, ss);
	mmiohandler.MMIOInitialize();
	cpu.setMmio(&mmiohandler);

	auto mainThread = tm.create(ep, sp + 0x100000);
	//mainThread->regs.X1 = mainThread->handle;
	mainThread->resume();

	tm.start();
}

ghandle Ctu::duplicateHandle(KObject *ptr) {
	for(auto elem : handles)
		if(elem.second.get() == ptr)
			return newHandle(elem.second);
	return 0;
}

void Ctu::deleteHandle(ghandle handle) {
	if(handles.find(handle) != handles.end()) {
		auto hnd = getHandle<KObject>(handle);
		handles.erase(handle);
		hnd->close();
	}
}
