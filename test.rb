require 'ptrace'

pt = PTrace.exec(ARGV.shift)
pt.wait
pt.cont

while e = pt.wait
  p e
  case e
  when :SIGTRAP
    pt.cont :SIGUSR1
  when :SIGSEGV
    pt.syscall :SIGSEGV
  when :SIGUSR1
    pt.singlestep
  else
    pt.syscall e
  end
end
