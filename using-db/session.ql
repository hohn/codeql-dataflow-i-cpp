/**
 * @name Format string injection
 * @id cpp/format-string-injection
 * @kind path-problem
 */

// printf("Name: %s, Age: %d", "Freddie", 2);

import cpp
// from FunctionCall fc
// where fc.getTarget().hasName("printf")
// select fc
// from FormattingFunctionCall printfCall
// where not printfCall.getFormat() instanceof StringLiteral
// select printfCall, printfCall.getFormat()
import semmle.code.cpp.dataflow.DataFlow

// from DataFlow::Node nodeFrom, DataFlow::Node sourceNode
// where not DataFlow::localFlowStep(nodeFrom, sourceNode)
// select sourceNode

predicate isSourceNode(DataFlow::Node sourceNode) {
  // explicit version:
  not exists(DataFlow::Node nodeFrom | DataFlow::localFlowStep(nodeFrom, sourceNode))
}

// class SourceNode extends DataFlow::Node {
//   SourceNode() {
//     not exists(DataFlow::Node nodeFrom | DataFlow::localFlowStep(nodeFrom, this))
//   }
// }

// from SourceNode sn 
// select sn

// 
// Do not want flow from non-constant to format string.
//
// from FormattingFunctionCall printfCall, DataFlow::Node source, 
//   DataFlow::Node formatStringArgument
// where printfCall.getFormat() = formatStringArgument.asExpr() 
// and DataFlow::localFlow(source, formatStringArgument) 
// and not source.asExpr() instanceof StringLiteral
// select source, printfCall, printfCall.getFormat()

// a = argv[1];
// printf(concat(a,b), c)
//

import cpp 
import semmle.code.cpp.dataflow.TaintTracking

class SourceNode extends DataFlow::Node {
  SourceNode() {
    not exists(DataFlow::Node nodeFrom | TaintTracking::localTaintStep(nodeFrom, this))
  }
}

// from FormattingFunctionCall printfCall, DataFlow::Node source, 
//   DataFlow::Node formatStringArgument
// where printfCall.getFormat() = formatStringArgument.asExpr() 
// and TaintTracking::localTaintStep(source, formatStringArgument) 
// and not source.asExpr() instanceof StringLiteral
// select source, printfCall, printfCall.getFormat()

// while (read(fd, &auxvEntry, sizeof(elf_aux_entry)) == sizeof(elf_aux_entry))

// import external data sources
import semmle.code.cpp.security.Security

//
// 1. Find user input -- source
//
// from SecurityOptions opts, DataFlow::Node source
// where opts.isUserInput(source.asExpr(), _)
// select source 


// 2. data sink -- formatting function call

// from FormattingFunctionCall printfCall, DataFlow::Node source, 
//   DataFlow::Node formatStringArgument
// where printfCall.getFormat() = formatStringArgument.asExpr() 
// and TaintTracking::localTaintStep(source, formatStringArgument) 
// and not source.asExpr() instanceof StringLiteral
// select source, printfCall, printfCall.getFormat()


// 3. connect them globally


import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.security.Security

class TaintedFormatConfig extends TaintTracking::Configuration {
  TaintedFormatConfig() { this = "TaintedFormatConfig" }

  override predicate isSource(DataFlow::Node source) {
    /* TBD */
    exists(SecurityOptions opts |
     opts.isUserInput(source.asExpr(), _)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    /* TBD */
    exists(FormattingFunctionCall printfCall | 
      printfCall.getFormat() = sink.asExpr() 
    )
  }
}

import DataFlow::PathGraph

// from TaintedFormatConfig cfg, DataFlow::Node source, DataFlow::Node sink
// where cfg.hasFlow(source, sink)
// select sink, "This format string may be derived from a $@.", source, "user-controlled value"

from TaintedFormatConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "This format string may be derived from a $@.", source, "user-controlled value"

// codeql database analyse 