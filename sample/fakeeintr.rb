#
# fakeeintr.rb
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
  o.on('-v', '--verbose'){
    $verbose = true
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

if defined? PTrace::SYSCALL
  def syscall_name eax
    PTrace::SYSCALL[eax]
  end
else
  def syscall_name eax
    eax.to_s
  end
end

$n = 0
$intr_signal = :SIGALRM

def fake_eintr? name
  if $n < 100
    $n += 1
    true
  else
    $n = 0
    false
  end
end

def exec_trap ptrace
  regs = ptrace.getregs
  name = syscall_name regs.orig_eax
  puts "#{$is_call ? 'call:' : 'rtrn:'} #{name}" if $verbose

  $is_call = !$is_call

  if fake_eintr? name
    if $is_call # returning timing
      ptrace.syscall
    else
      ptrace.syscall $intr_signal
    end
  else
    ptrace.syscall # continue
  end
end

def trace_syscall ptrace
  $is_call = true

  ptrace.wait
  ptrace.syscall

  while e = ptrace.wait
    case e
    when :SIGTRAP
      exec_trap ptrace
    else
      if e == $intr_signal
        ptrace.syscall
      else
        ptrace.syscall e
      end
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

puts "PID: #{ptrace.pid}" if $verbose
trace_syscall(ptrace)

