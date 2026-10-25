-module(policy_file_ffi).
-export([write/2, write/3, write/4, windows_command/4]).
-include_lib("kernel/include/file.hrl").

write(Path, Contents) ->
    case write(Path, Contents, fun file:write/2) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
    end.

%% Keep the write operation injectable to test an interruption after partial I/O.
write(Path, Contents, Write) ->
    write(Path, Contents, Write, fun replace/2).

write(Path, Contents, Write, Replace) ->
    case destination(Path, 40) of
        {ok, Target, Metadata} ->
            prepare(Target, Contents, Metadata, Write, Replace);
        Error -> Error
    end.

destination(_Path, 0) ->
    {error, eloop};
destination(Path, Remaining) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = symlink}} ->
            case file:read_link(Path) of
                {ok, Link} ->
                    destination(filename:join(filename:dirname(Path), Link), Remaining - 1);
                Error -> Error
            end;
        {ok, #file_info{type = regular, mode = Mode, uid = User, gid = Group}} ->
            {ok, Path, #file_info{mode = Mode, uid = User, gid = Group}};
        {error, enoent} ->
            {ok, Path, new};
        {ok, _Info} -> {error, einval};
        Error -> Error
    end.

prepare(Path, Contents, Metadata, Write, Replace) ->
    Suffix = integer_to_binary(erlang:unique_integer([positive, monotonic])),
    Temporary = <<Path/binary, ".licence-audit-", Suffix/binary, ".tmp">>,
    case create_temporary(Temporary, Path) of
        {ok, File} ->
            Outcome = try
                case prepare_file(File, Temporary, Contents, Metadata, Write) of
                    ok ->
                        case file:close(File) of
                            ok -> Replace(Temporary, Path);
                            Error -> Error
                        end;
                    Error -> Error
                end
            catch
                CaughtClass:CaughtReason:CaughtStack ->
                    {raised, CaughtClass, CaughtReason, CaughtStack}
            after
                file:close(File)
            end,
            finish_write(Outcome, Temporary);
        {error, eexist} -> prepare(Path, Contents, Metadata, Write, Replace);
        Error -> Error
    end.

finish_write({error, {helper_not_stopped, _}} = Outcome, _Temporary) ->
    %% Do not race a helper whose termination could not be confirmed.
    Outcome;
finish_write(Outcome, Temporary) ->
    case {Outcome, cleanup_temporary(Temporary)} of
        {{raised, Class, Reason, Stack}, ok} ->
            erlang:raise(Class, Reason, Stack);
        {Result, ok} -> Result;
        {_, {error, Reason}} ->
            {error, {temporary_cleanup_failed, Temporary, Reason}}
    end.

create_temporary(Temporary, Target) ->
    case os:type() of
        {win32, _} ->
            case windows_command(Temporary, Target, create_script(), 60000) of
                ok ->
                    case file:open(Temporary, [write, binary, raw]) of
                        {ok, _} = Opened -> Opened;
                        Error ->
                            case cleanup_temporary(Temporary) of
                                ok -> Error;
                                CleanupError -> CleanupError
                            end
                    end;
                {error, {windows_command, 2, _}} -> {error, eexist};
                Error -> Error
            end;
        _ -> file:open(Temporary, [write, binary, exclusive, raw])
    end.

prepare_file(File, Path, Contents, Metadata, Write) ->
    case file:read_file_info(File) of
        {ok, #file_info{mode = DefaultMode}} ->
            case file:change_mode(Path, 8#600) of
                ok ->
                    case Write(File, Contents) of
                        ok ->
                            case file:sync(File) of
                                ok -> preserve_metadata(Path, Metadata, DefaultMode);
                                Error -> Error
                            end;
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

preserve_metadata(Path, new, DefaultMode) ->
    file:change_mode(Path, DefaultMode);
preserve_metadata(Path, Metadata, _DefaultMode) ->
    file:write_file_info(Path, Metadata).

cleanup_temporary(Path) ->
    case os:type() of
        {win32, _} ->
            %% Windows readonly is a file attribute, not an unlink permission.
            case file:change_mode(Path, 8#600) of
                ok -> delete_temporary(Path);
                {error, enoent} -> ok;
                {error, ModeReason} ->
                    case delete_temporary(Path) of
                        ok -> ok;
                        {error, Reason} -> {error, {ModeReason, Reason}}
                    end
            end;
        _ -> delete_temporary(Path)
    end.

delete_temporary(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        Error -> Error
    end.

replace(From, To) ->
    case os:type() of
        {win32, _} ->
            windows_command(From, To, [
                "if($native.GetMethod('MoveFileExW').Invoke($null,@($from,$to,[uint32]9)))",
                "{exit 0}else{exit 1}"
            ], 60000);
        _ -> file:rename(From, To)
    end.

create_script() ->
    [
        "$sections=[Security.AccessControl.AccessControlSections]'Access,Owner,Group';",
        "$security=New-Object Security.AccessControl.FileSecurity;",
        "if([IO.File]::Exists($to)){",
        "$security.SetSecurityDescriptorSddlForm(",
        "[IO.File]::GetAccessControl($to,$sections).GetSecurityDescriptorSddlForm($sections),",
        "$sections)",
        "}else{",
        "$user=[Security.Principal.WindowsIdentity]::GetCurrent().User;",
        "$security.SetOwner($user);",
        "$security.SetAccessRuleProtection($true,$false);",
        "$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(",
        "$user,[Security.AccessControl.FileSystemRights]::FullControl,",
        "[Security.AccessControl.AccessControlType]::Allow)))",
        "};",
        "$created=$false;try{",
        "$stream=New-Object IO.FileStream($from,[IO.FileMode]::CreateNew,",
        "[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,",
        "[IO.FileOptions]::None,$security);",
        "$created=$true;$stream.Dispose();",
        "[IO.File]::SetAccessControl($from,$security)",
        "}catch{",
        "$exception=$_.Exception;",
        "if($created){[IO.File]::Delete($from)};",
        "while($exception.InnerException){$exception=$exception.InnerException};",
        "if(($exception.HResult -band 65535) -in @(80,183)){exit 2};throw",
        "};exit 0"
    ].

%% OTP's Windows rename moves the destination aside first. Call the same-volume
%% Win32 replacement directly, without a copy/delete fallback or disk-built NIF.
windows_command(From, To, Command, Timeout) ->
    Owner = self(),
    Reference = make_ref(),
    {Guardian, Monitor} = spawn_monitor(fun() ->
        process_flag(trap_exit, true),
        OwnerMonitor = monitor(process, Owner),
        Result = run_windows_command(From, To, Command, Timeout, OwnerMonitor),
        demonitor(OwnerMonitor, [flush]),
        Owner ! {Reference, Result}
    end),
    receive
        {Reference, Result} ->
            demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Guardian, Reason} ->
            {error, {helper_guard_failed, Reason}}
    end.

run_windows_command(From, To, Command, Timeout, OwnerMonitor) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(24)),
    Prefix = unicode:characters_to_binary(["$operation='", Nonce, "';"], utf8, {utf16, little}),
    Token = binary:part(base64:encode(Prefix), 0, byte_size(Prefix) div 3 * 4),
    Script = [
        "$operation='", Nonce, "';",
        "$ErrorActionPreference='Stop';",
        "$assembly=New-Object Reflection.AssemblyName('LicenceAuditAtomic');",
        "$module=[AppDomain]::CurrentDomain.DefineDynamicAssembly(",
        "$assembly,[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('Native');",
        "$type=$module.DefineType('Native',[Reflection.TypeAttributes]::Public);",
        "$method=$type.DefinePInvokeMethod('MoveFileExW','kernel32.dll',",
        "[Reflection.MethodAttributes]'Public,Static,PinvokeImpl',",
        "[Reflection.CallingConventions]::Standard,[bool],",
        "[Type[]]@([string],[string],[uint32]),",
        "[Runtime.InteropServices.CallingConvention]::Winapi,",
        "[Runtime.InteropServices.CharSet]::Unicode);",
        "$method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig);",
        "$native=$type.CreateType();",
        "$from=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('",
        base64:encode(filename:absname(From)), "'));",
        "$to=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('",
        base64:encode(filename:absname(To)), "'));",
        Command
    ],
    Encoded = base64:encode(unicode:characters_to_binary(Script, utf8, {utf16, little})),
    case os:getenv("SystemRoot") of
        false -> {error, enoent};
        SystemRoot ->
            Executable = filename:join([
                SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            ]),
            try open_port({spawn_executable, Executable}, [
                binary, exit_status, use_stdio, stderr_to_stdout, hide,
                {args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    binary_to_list(Encoded)]}
            ]) of
                Port ->
                    ProcessId = case erlang:port_info(Port, os_pid) of
                        {os_pid, Id} -> Id;
                        undefined -> undefined
                    end,
                    Native = #{port => Port, pid => ProcessId, token => Token,
                        system_root => SystemRoot},
                    Deadline = erlang:monotonic_time(millisecond) + Timeout,
                    try replacement_result(
                        Native, <<>>, Deadline, OwnerMonitor, From
                    )
                    catch
                        Class:Reason ->
                            abort_helper(Native, From, {helper_guard_failed, Class, Reason})
                    end
            catch
                error:Reason -> {error, Reason}
            end
    end.

replacement_result(Native, Output, Deadline, OwnerMonitor, Temporary) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> abort_helper(Native, Temporary, timeout);
        false -> receive_result(
            Native, Output, Deadline, OwnerMonitor, Temporary, Remaining
        )
    end.

receive_result(Native, Output, Deadline, OwnerMonitor, Temporary, Remaining) ->
    #{port := Port} = Native,
    receive
        {Port, {data, Data}} ->
            Combined = <<Output/binary, Data/binary>>,
            Start = max(0, byte_size(Combined) - 8192),
            replacement_result(
                Native, binary:part(Combined, Start, byte_size(Combined) - Start),
                Deadline, OwnerMonitor, Temporary
            );
        {Port, {exit_status, 0}} -> ok;
        {Port, {exit_status, Status}} -> {error, {windows_command, Status, Output}};
        {'EXIT', Port, Reason} ->
            abort_helper(Native, Temporary, {helper_port_closed, Reason});
        {'DOWN', OwnerMonitor, process, _Owner, _Reason} ->
            Result = abort_helper(Native, Temporary, owner_died),
            case Result of
                {error, owner_died} -> ok;
                {error, Reason} ->
                    logger:error("Could not stop and clean policy helper ~ts: ~tp",
                        [Temporary, Reason])
            end,
            Result
    after Remaining ->
        abort_helper(Native, Temporary, timeout)
    end.

abort_helper(Native, Temporary, Failure) ->
    case terminate_and_await(Native) of
        ok ->
            case cleanup_temporary(Temporary) of
                ok -> {error, Failure};
                {error, Reason} -> {error, {temporary_cleanup_failed, Temporary, Reason}}
            end;
        {error, Reason} -> {error, {helper_not_stopped, Reason}}
    end.

terminate_and_await(#{port := NativePort, pid := ProcessId, token := Token,
        system_root := SystemRoot}) ->
    Filter = case ProcessId of
        undefined -> ["CommandLine LIKE '%", Token, "%'"];
        _ -> ["ProcessId=", integer_to_list(ProcessId)]
    end,
    %% Hold a native process handle, then verify the unique launch token again.
    %% PID reuse must never let cancellation kill an unrelated process.
    Script = [
        "$ErrorActionPreference='Stop';$process=$null;try{",
        "$token='", Token, "';",
        "$candidates=@(Get-CimInstance Win32_Process -Filter \"", Filter,
        "\" -OperationTimeoutSec 3);",
        "if($candidates.Count -eq 0){exit 0};",
        "if($candidates.Count -ne 1){exit 1};",
        "$id=[int]$candidates[0].ProcessId;",
        "try{$process=[Diagnostics.Process]::GetProcessById($id)}",
        "catch [ArgumentException]{exit 0};",
        "$null=$process.Handle;",
        "$actual=Get-CimInstance Win32_Process -Filter \"ProcessId=$id\"",
        " -OperationTimeoutSec 3;",
        "if(!$actual){exit 0};",
        "if(!$actual.CommandLine.Contains($token)){exit 0};",
        "$process.Kill();",
        "if(!$process.WaitForExit(5000)){exit 1};exit 0",
        "}catch{exit 1}finally{if($process){$process.Dispose()}}"
    ],
    Encoded = base64:encode(unicode:characters_to_binary(Script, utf8, {utf16, little})),
    Executable = filename:join([
        SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    ]),
    Result = try open_port({spawn_executable, Executable}, [
                binary, exit_status, use_stdio, stderr_to_stdout, hide,
                {args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    binary_to_list(Encoded)]}
            ]) of
                Killer ->
                    await_controller(Killer, erlang:monotonic_time(millisecond) + 15000)
            catch
                error:Reason -> {error, Reason}
            end,
    case Result of
        ok ->
            close_port(NativePort),
            ok;
        Error -> Error
    end.

await_controller(Port, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            close_port(Port),
            {error, controller_timeout};
        false ->
            receive
                {Port, {data, _}} -> await_controller(Port, Deadline);
                {Port, {exit_status, 0}} -> ok;
                {Port, {exit_status, Status}} -> {error, {controller_failed, Status}};
                {'EXIT', Port, Reason} -> {error, {controller_port_closed, Reason}}
            after Remaining ->
                close_port(Port),
                {error, controller_timeout}
            end
    end.

close_port(Port) ->
    try port_close(Port) of
        true -> ok
    catch
        error:badarg -> ok
    end.
