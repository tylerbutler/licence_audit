-module(sbom_version_ffi).
-export([set_cwd/1]).

%% Test-only helper for proving the SBOM tool version comes from the build,
%% never from whatever project happens to be in the current working
%% directory. Adapts Erlang's `ok | {error, Reason}` shape to the
%% `Result(Nil, Nil)` shape Gleam expects from `@external`.
set_cwd(Dir) ->
    case file:set_cwd(Dir) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
    end.
