#
# Mini system call tracer
#

require 'optparse'
require 'ptrace'

opt = OptionParser.new{|o|
  o.on('-p', '--pid PID'){|pid|
    $pid = pid.to_i
  }
  o.on('--unistd UNISTD_FILE_PATH'){|us|
    # for exmaple: '/usr/include/asm-i486/unistd.h'
    $uni_std_file_path = us
  }
}

opt.parse!(ARGV)

if defined?($uni_std_file_path)
  # read syscall number information
  class PTrace
    SYSCALL = Hash.new
    File.read($uni_std_file_path).each_line{|line|
      /\#define __NR_(\S+)\s+(\d+)/ =~ line
      SYSCALL[$2.to_i] = $1
    }
  end
end

def exec_trap ptrace
  regs = ptrace.getregs
  if defined? PTrace::SYSCALL
    sc = PTrace::SYSCALL[regs.orig_eax]
  else
    sc = regs.orig_eax
  end
  puts "#{$direc ? '<=' : '=>'} #{sc}"
  if sc == 'write'
    fd = regs.ebx
    ptr = regs.ecx
    size = regs.edx
    str = ''
    size.times{|i|
      str << (ptrace.peekdata(ptr + i) & 0xff).chr
    }
    p [fd, ptr, str, size]
  end
  $direc = !$direc
  ptrace.syscall
end

def trace_syscall ptrace
  ptrace.wait
  ptrace.syscall
  $direc = true
  while e = ptrace.wait
    case e
    when :SIGTRAP
      exec_trap ptrace
    else
      ptrace.syscall e
    end
  end
end

if defined?($pid)
  ptrace = PTrace.attach($pid)
elsif ARGV.empty?
  puts opt.help
  exit
else
  ptrace = PTrace.exec(ARGV.join(' '))
end

trace_syscall(ptrace)

