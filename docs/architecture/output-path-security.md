# Output Path Security

Output paths are resolved canonically before inspection. Windows comparison is
case-insensitive. Target roots, target Git common directories, configured
protected roots, and symlink or junction aliases into them are rejected.
Evidence may be written only under the verifier repository or an explicitly
authorised external evidence root.
