-module(policy_file_ffi).
-export([write/2, write/3]).
-include_lib("kernel/include/file.hrl").

write(Path, Contents) ->
    case write(Path, Contents, fun file:write/2) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
    end.

%% Keep the write operation injectable to test an interruption after partial I/O.
write(Path, Contents, Write) ->
    case destination(Path, 40) of
        {ok, Target, Metadata} ->
            prepare(Target, Contents, Metadata, Write);
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

prepare(Path, Contents, Metadata, Write) ->
    Suffix = integer_to_binary(erlang:unique_integer([positive, monotonic])),
    Temporary = <<Path/binary, ".licence-audit-", Suffix/binary, ".tmp">>,
    case file:open(Temporary, [write, binary, exclusive, raw]) of
        {ok, File} ->
            try
                case prepare_file(File, Temporary, Contents, Metadata, Write) of
                    ok ->
                        case file:close(File) of
                            ok -> replace(Temporary, Path);
                            Error -> Error
                        end;
                    Error -> Error
                end
            after
                file:close(File),
                file:delete(Temporary)
            end;
        {error, eexist} -> prepare(Path, Contents, Metadata, Write);
        Error -> Error
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

replace(From, To) ->
    case os:type() of
        {win32, _} -> windows_replace(From, To);
        _ -> file:rename(From, To)
    end.

%% OTP's Windows rename moves the destination aside first. Call the same-volume
%% Win32 replacement directly, without a copy/delete fallback or disk-built NIF.
windows_replace(From, To) ->
    Script = [
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
        "if([IO.File]::Exists($to)){",
        "$sections=[Security.AccessControl.AccessControlSections]'Access,Owner,Group';",
        "$security=New-Object Security.AccessControl.FileSecurity;",
        "$security.SetSecurityDescriptorSddlForm(",
        "[IO.File]::GetAccessControl($to,$sections).GetSecurityDescriptorSddlForm($sections),",
        "$sections);",
        "[IO.File]::SetAccessControl($from,$security);",
        "};",
        "if($native.GetMethod('MoveFileExW').Invoke($null,@($from,$to,[uint32]9)))",
        "{exit 0}else{exit 1}"
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
                Port -> replacement_result(Port, <<>>)
            catch
                error:Reason -> {error, Reason}
            end
    end.

replacement_result(Port, Output) ->
    receive
        {Port, {data, Data}} ->
            Combined = <<Output/binary, Data/binary>>,
            Start = max(0, byte_size(Combined) - 8192),
            replacement_result(Port, binary:part(Combined, Start, byte_size(Combined) - Start));
        {Port, {exit_status, 0}} -> ok;
        {Port, {exit_status, Status}} -> {error, {windows_replace, Status, Output}}
    after 60000 ->
        port_close(Port),
        {error, timeout}
    end.
