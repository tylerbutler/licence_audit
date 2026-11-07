export function stderr(message) {
  process.stderr.write(message);
  return undefined;
}

export function exit_with(code) {
  process.exit(code);
  return undefined;
}
