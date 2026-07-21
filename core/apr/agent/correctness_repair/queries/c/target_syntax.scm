(function_definition
  declarator: (function_declarator
    parameters: (parameter_list
      (parameter_declaration) @target.parameter)))

(declaration) @declaration

(call_expression
  function: (_) @call.function
  arguments: (argument_list) @call.arguments) @call

(assignment_expression
  left: (_) @assignment.left
  right: (_) @assignment.right) @assignment

(update_expression) @update

(return_statement) @return

(if_statement
  condition: (_) @control.condition) @control.if

(switch_statement
  condition: (_) @control.condition) @control.switch

(conditional_expression
  condition: (_) @control.condition) @control.conditional
