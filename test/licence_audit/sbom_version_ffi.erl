-module(sbom_version_ffi).
-export([with_cwd/2]).

%% Test-only helper for proving the SBOM tool version comes from the build,
%% never from whatever project happens to be in the current working
%% directory. Runs `Fun` with the process working directory set to `Dir`,
%% then always restores the original directory via `after`, even if `Fun`
%% panics (a Gleam panic is an Erlang exception, and `after` still runs).
with_cwd(Dir, Fun) ->
    {ok, OriginalCwd} = file:get_cwd(),
    try
        ok = file:set_cwd(Dir),
        Fun()
    after
        ok = file:set_cwd(OriginalCwd)
    end.
