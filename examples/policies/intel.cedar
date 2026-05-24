// Intel access guardrails:
// - Must be within working hours.
// - SECRET/TOP_SECRET require being onsite.
// - TOP_SECRET also requires being in US.

permit(principal, action, resource)
when {
  context.is_structural_allowed == true
  && context.is_working_hours == true
  && (
    context.clearance == "confidential"
    || (context.clearance == "secret" && context.is_onsite == true)
    || (context.clearance == "top_secret" && context.is_onsite == true && context.country == "US")
  )
};
