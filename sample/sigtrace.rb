#
# SIGNAL Tracer
#

require 'ptrace'
require 'pp'

ptrace = PTrace.exec(*ARGV)
puts "pid: #{ptrace.pid}"

ptrace.wait
ptrace.cont
i = 0
e = 0

while e = ptrace.wait
  si = ptrace.getsiginfo
  pp [i+=1, e, si]
  if e == :SIGTRAP
    ptrace.cont
  else
    ptrace.singlestep e
  end
end

