import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { Ok, Error as GleamError } from "../../gleam.mjs";

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// Keep ".." until after symbolic links have been followed. path.resolve and
// path.normalize would erase that distinction before the filesystem sees it.
/** @param {string} filename @returns {[string, string[]]} */
function components(filename) {
  const root = path.parse(filename).root;
  const separator = process.platform === "win32" ? /[/\\]+/ : /\/+/;
  return [root, filename.slice(root.length).split(separator)];
}

/**
 * @param {string} root
 * @param {string[]} pending
 * @param {number} followed
 * @returns {Ok | GleamError} Result(String, String)
 */
function resolveComponents(root, pending, followed) {
  let current = root;
  for (let index = 0; index < pending.length; index += 1) {
    const component = pending[index];
    if (component === "" || component === ".") continue;
    if (component === "..") {
      current = path.dirname(current);
      continue;
    }
    const candidate = path.join(current, component);
    let information;
    try {
      information = fs.lstatSync(candidate);
    } catch (error) {
      if (error instanceof Error && error.code === "ENOENT") {
        current = candidate;
        continue;
      }
      throw error;
    }
    if (information.isSymbolicLink()) {
      if (followed >= 40) {
        return new GleamError(`too many symbolic links at ${candidate}`);
      }
      let target;
      try {
        target = decoder.decode(fs.readlinkSync(candidate, { encoding: "buffer" }));
      } catch (error) {
        if (error instanceof TypeError && error.code === "ERR_ENCODING_INVALID_ENCODED_DATA") {
          return new GleamError(`symbolic link target is not UTF-8: ${candidate}`);
        }
        throw error;
      }
      const absolute = path.isAbsolute(target)
        ? target
        : current + path.sep + target;
      const [targetRoot, targetComponents] = components(absolute);
      return resolveComponents(
        targetRoot,
        targetComponents.concat(pending.slice(index + 1)),
        followed + 1,
      );
    }
    if (index < pending.length - 1 && !information.isDirectory()) {
      return new GleamError(`path component is not a directory: ${candidate}`);
    }
    // Native spelling also unifies case aliases on case-insensitive volumes.
    current = fs.realpathSync(candidate);
  }
  return new Ok(process.platform === "win32" ? current.replaceAll("\\", "/") : current);
}

/** @param {string} filename @returns {Ok | GleamError} Result(String, String) */
export function canonical_path(filename) {
  if (filename === "" || filename.includes("\0")) {
    return new GleamError("empty path or NUL in path");
  }
  // Drive-relative Windows paths depend on a per-drive working directory.
  // Refuse those ambiguous paths instead of silently normalising away "..".
  if (process.platform === "win32" && /^[A-Za-z]:[^/\\]/.test(filename)) {
    return new GleamError("drive-relative paths are not supported; use an absolute path");
  }
  try {
    const absolute = path.isAbsolute(filename)
      ? filename
      : process.cwd() + path.sep + filename;
    const [root, pending] = components(absolute);
    return resolveComponents(root, pending, 0);
  } catch (error) {
    // Only operational filesystem failures become typed errors. Defects in
    // this wrapper (including unexpected JS values) remain process failures.
    if (
      error instanceof Error
      && typeof error.code === "string"
      && typeof error.syscall === "string"
    ) {
      return new GleamError(`${error.code}: ${error.message}`);
    }
    throw error;
  }
}
