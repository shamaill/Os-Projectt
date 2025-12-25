cat tracer.py
#!/usr/bin/env python3
"""
Cloud-Enabled System Call Tracer - On-Demand Mode
Traces any command specified in SSM Parameter Store
"""

import boto3
import subprocess
import json
import time
import signal
import sys
from datetime import datetime

# AWS Configuration
REGION = "ap-southeast-2"  # Change if needed
LOG_GROUP = "/syscalls/demo"
SSM_TOGGLE = "/syscalls/enabled"
SSM_COMMAND = "/syscalls/target_command"
POLL_INTERVAL = 5

ssm_client = boto3.client('ssm', region_name=REGION)
logs_client = boto3.client('logs', region_name=REGION)

strace_process = None
sequence_token = None
current_log_stream = None

def setup_aws_resources():
    """Create CloudWatch log group and SSM parameters"""
    try:
        logs_client.create_log_group(logGroupName=LOG_GROUP)
        print(f"✅ Created log group: {LOG_GROUP}")
    except logs_client.exceptions.ResourceAlreadyExistsException:
        print(f"✅ Log group exists: {LOG_GROUP}")
    
    try:
        ssm_client.put_parameter(Name=SSM_TOGGLE, Value='false', Type='String')
        print(f"✅ Created toggle: {SSM_TOGGLE}")
    except:
        print(f"✅ Toggle exists: {SSM_TOGGLE}")
    
    try:
        ssm_client.put_parameter(Name=SSM_COMMAND, Value='ls -la', Type='String')
        print(f"✅ Created command param: {SSM_COMMAND}")
    except:
        print(f"✅ Command param exists: {SSM_COMMAND}")

def create_log_stream():
    global sequence_token, current_log_stream
    current_log_stream = f"trace-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    try:
        logs_client.create_log_stream(
            logGroupName=LOG_GROUP,
            logStreamName=current_log_stream
        )
        sequence_token = None
    except:
        pass

def get_ssm_parameter(param_name):
    try:
        response = ssm_client.get_parameter(Name=param_name)
        return response['Parameter']['Value']
    except:
        return None

def is_tracing_enabled():
    value = get_ssm_parameter(SSM_TOGGLE)
    return value and value.lower() == 'true'

def get_target_command():
    return get_ssm_parameter(SSM_COMMAND) or "ls -la"

def send_to_cloudwatch(message):
    global sequence_token
    try:
        log_event = {
            'logGroupName': LOG_GROUP,
            'logStreamName': current_log_stream,
            'logEvents': [{
                'timestamp': int(time.time() * 1000),
                'message': json.dumps(message) if isinstance(message, dict) else str(message)
            }]
        }
        if sequence_token:
            log_event['sequenceToken'] = sequence_token
        
        response = logs_client.put_log_events(**log_event)
        sequence_token = response.get('nextSequenceToken')
    except Exception as e:
        print(f"❌ CloudWatch error: {e}")

def start_tracing(command):
    global strace_process
    print(f"\n🔍 TRACING: {command}")
    create_log_stream()
    
    send_to_cloudwatch({
        'event': 'trace_started',
        'command': command,
        'timestamp': datetime.now().isoformat()
    })
    
    try:
        strace_process = subprocess.Popen(
            ['strace', '-f', '-tt', '-T', '-s', '256'] + command.split(),
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        line_count = 0
        for line in strace_process.stderr:
            if line.strip():
                parsed = {
                    'timestamp': datetime.now().isoformat(),
                    'syscall': line.strip()
                }
                send_to_cloudwatch(parsed)
                line_count += 1
                
                # Print sample (first 10 lines)
                if line_count <= 10:
                    print(f"  → {line.strip()[:70]}")
                elif line_count == 11:
                    print(f"  ... (streaming to CloudWatch)")
            
            if not is_tracing_enabled():
                print("\n⏹️  Toggle turned OFF - Stopping trace")
                stop_tracing()
                break
        
        strace_process.wait()
        send_to_cloudwatch({
            'event': 'trace_completed',
            'total_syscalls': line_count,
            'timestamp': datetime.now().isoformat()
        })
        print(f"✅ Trace completed - {line_count} syscalls logged")
        
    except Exception as e:
        print(f"❌ Error tracing: {e}")
    finally:
        strace_process = None

def stop_tracing():
    global strace_process
    if strace_process:
        strace_process.terminate()
        strace_process = None

def signal_handler(sig, frame):
    print("\n\n👋 Shutting down...")
    stop_tracing()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 60)
    print("☁️  CLOUD-ENABLED SYSCALL TRACER - ON-DEMAND MODE")
    print("=" * 60)
    
    setup_aws_resources()
    
    print(f"\n📊 Configuration:")
    print(f"   CloudWatch Log Group: {LOG_GROUP}")
    print(f"   Toggle Parameter:     {SSM_TOGGLE}")
    print(f"   Command Parameter:    {SSM_COMMAND}")
    print(f"   Poll Interval:        {POLL_INTERVAL}s")
    print("\n" + "=" * 60)
    print("🎯 ON-DEMAND USAGE:")
    print("   1. Set command:  aws ssm put-parameter --name /syscalls/target_command --value 'YOUR_COMMAND' --overwrite")
    print("   2. Start trace:  aws ssm put-parameter --name /syscalls/enabled --value true --overwrite")
    print("   3. Stop trace:   aws ssm put-parameter --name /syscalls/enabled --value false --overwrite")
    print("=" * 60)
    
    print("\n⏳ Monitoring for trace requests...\n")
    
    last_status = False
    while True:
        enabled = is_tracing_enabled()
        
        if enabled and not last_status:
            command = get_target_command()
            print(f"\n🚀 Trace request detected!")
            print(f"   Command: {command}")
            start_tracing(command)
            
            # Auto-disable after trace completes
            ssm_client.put_parameter(
                Name=SSM_TOGGLE,
                Value='false',
                Overwrite=True
            )
            print("   Auto-disabled toggle")
        
        last_status = enabled
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
