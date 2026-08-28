-module(version_ffi).
-export([build_version/0]).

%% Reads the licence_audit release version from the compiled OTP application
%% resource (the `vsn` baked in from this project's own gleam.toml at build
%% time). This is independent of the current working directory, so auditing
%% another project can never leak that project's version into tool metadata.
build_version() ->
    _ = application:load(licence_audit),
    case application:get_key(licence_audit, vsn) of
        {ok, Vsn} -> {ok, unicode:characters_to_binary(Vsn)};
        undefined -> {error, nil}
    end.
