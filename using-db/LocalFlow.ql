/**
 * @name Non-constant format string
 * @id cpp/non-constant-format-string
 * @kind problem
 */
import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.commons.Printf

class SourceNode extends DataFlow::Node {
  SourceNode() {
    not DataFlow::localFlowStep(_, this)
  }
}

from FormattingFunctionCall printfCall, SourceNode src, DataFlow::Node formatStringArg
where
  formatStringArg.asExpr() = printfCall.getFormat() and
  DataFlow::localFlow(src, formatStringArg) and
  not src.asExpr() instanceof StringLiteral
select formatStringArg, "Non-constant format string from $@.", src, src.toString()

