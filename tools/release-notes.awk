# Print the body beneath exactly one canonical changelog heading.
# The caller supplies heading, which includes the display version and tag URL.
index($0, heading) == 1 {
  matches++
  if (matches == 1) {
    inside = 1
  }
  next
}

inside && /^## / {
  inside = 0
}

inside {
  notes = notes $0 ORS
  if ($0 !~ /^[[:space:]]*$/) {
    body = 1
  }
}

END {
  if (matches == 0) {
    printf "CHANGELOG.md has no release section for %s\n", heading > "/dev/stderr"
    exit 1
  }
  if (matches > 1) {
    printf "CHANGELOG.md has more than one release section for %s\n", heading > "/dev/stderr"
    exit 1
  }
  if (!body) {
    printf "CHANGELOG.md has an empty release section for %s\n", heading > "/dev/stderr"
    exit 1
  }
  printf "%s", notes
}
