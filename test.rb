require 'ptrace'

class PTrace
  def initialize
    pid = fork{
      yield
    }
    self.__attach__(pid)
    __set_pid__ pid
  end
end

ptrace = PTrace.new{
  p [$$, :hello]
  Process.kill :USR1, $$
}

while e = ptrace.wait
  case e
  when :SIGTRAP
    p [e, ptrace.getregs.orig_eax]
    ptrace.syscall
  else
    ptrace.syscall e
  end
end

