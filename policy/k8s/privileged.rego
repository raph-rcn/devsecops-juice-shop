package main
deny[msg] {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.containers[i]
  c.securityContext.privileged == true
  msg := sprintf("Privileged container %s not allowed", [c.name])
}
