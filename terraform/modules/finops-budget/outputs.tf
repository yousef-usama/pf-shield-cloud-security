output "budget_id" {
  description = "The ID of the provisioned AWS Budget"
  value       = aws_budgets_budget.pf_shield_zero_cost_guardrail.id
}

output "budget_name" {
  description = "The name of the provisioned AWS Budget"
  value       = aws_budgets_budget.pf_shield_zero_cost_guardrail.name
}

output "budget_limit" {
  description = "The monthly budget limit in USD"
  value       = aws_budgets_budget.pf_shield_zero_cost_guardrail.limit_amount
}
