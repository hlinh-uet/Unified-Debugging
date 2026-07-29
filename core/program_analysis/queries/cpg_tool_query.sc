import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import java.nio.file.{Files, Paths}

@main def main(
  cpgPath: String,
  tool: String,
  symbols: String,
  query: String,
  kinds: String,
  regionIds: String,
  regionSpans: String,
  sourcePath: String,
  functionName: String,
  functionSignature: String,
  functionStartLine: String,
  limit: String,
  outputPath: String
): Unit = {
  importCpg(cpgPath)

  val requestedLimit = scala.util.Try(limit.toInt).getOrElse(12).max(1)
  val maxResults =
    if (tool == "get_target_behavior_analysis") requestedLimit.min(256)
    else requestedLimit.min(64)
  val names = splitParam(symbols).take(24)
  val sourceNorm = sourcePath.replace("\\", "/")
  val fn = functionName
  val fnStart = scala.util.Try(functionStartLine.toInt).getOrElse(0)
  val requestedRegionIds = splitParam(regionIds).take(24)
  val canonicalRegionSpans = parseRegionSpans(regionSpans)
  val resolvedRegionSpans = canonicalRegionSpans
  val rawResults = tool match {
    case "get_target_behavior_analysis" => targetBehaviorAnalysis(sourceNorm, fn, functionSignature, fnStart, resolvedRegionSpans, maxResults)
    case "get_callers" => callerResults(names, maxResults)
    case "get_callees" => calleeResults(names, sourceNorm, fn, functionSignature, fnStart, maxResults)
    case "get_symbol_usages" => symbolUsageResults(names, maxResults)
    case "get_type_or_macro_definition" => typeOrMacroResults(names, maxResults)
    case "get_control_data_dependencies" => controlDataResults(names, sourceNorm, fn, functionSignature, fnStart, resolvedRegionSpans, maxResults)
    case "get_target_region_evidence" => targetRegionResults(names, sourceNorm, fn, functionSignature, fnStart, resolvedRegionSpans, maxResults)
    case "get_semantic_context_bundle" => semanticContextBundle(names, sourceNorm, fn, functionSignature, fnStart, resolvedRegionSpans, maxResults)
    case "get_behavior_evidence" => behaviorEvidence(splitParam(kinds), names, sourceNorm, fn, functionSignature, fnStart, resolvedRegionSpans, maxResults)
    case "search_cpg_evidence" => searchResults(splitParam(symbols) ++ terms(query), splitParam(kinds), maxResults)
    case _ => List[String]()
  }
  val results =
    if (Set("get_target_region_evidence", "get_control_data_dependencies").contains(tool))
      filterResultsByRegions(rawResults, resolvedRegionSpans, requestedRegionIds)
    else rawResults
  val behaviorTargetCount =
    if (tool == "get_target_behavior_analysis")
      targetMethods(sourceNorm, fn, functionSignature, fnStart)
        .count(m => fnStart <= 0 || line(m) == fnStart)
    else 1
  val uncertainty =
    (if (results.isEmpty) List(s"joern_cpg_tool_returned_no_results:${tool}") else List[String]()) ++
    fileMatchUncertainties(sourceNorm, fn, functionSignature, fnStart) ++
    (if (requestedRegionIds.nonEmpty && canonicalRegionSpans.isEmpty) List("canonical_region_spans_missing") else List[String]()) ++
    regionUncertainties(requestedRegionIds, resolvedRegionSpans, rawResults, results) ++
    (if (tool == "get_target_behavior_analysis" && behaviorTargetCount != 1)
      List(s"joern_exact_target_method_count:${behaviorTargetCount}")
    else List[String]()) ++
    (if (tool == "get_target_behavior_analysis" && results.distinct.size > maxResults)
      List(s"joern_target_behavior_truncated:${results.distinct.size}:${maxResults}")
    else List[String]())
  val json = s"""{"provider":"joern","query":"cpg_tool_query","tool":"${esc(tool)}","raw_result_count":${results.distinct.size},"results":[${results.distinct.take(maxResults).mkString(",")}],"uncertainties":[${uncertainty.map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
  Files.write(Paths.get(outputPath), json.getBytes("UTF-8"))
}

def targetBehaviorAnalysis(
  sourcePath: String, functionName: String, functionSignature: String,
  functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int
): List[String] = {
  val methods = targetMethods(sourcePath, functionName, functionSignature, functionStartLine)
    .filter(m => functionStartLine <= 0 || line(m) == functionStartLine)
  if (methods.size != 1) {
    return List[String]()
  }
  val m = methods.head
  val nonOperatorCalls = m.call.nameNot("<operator>.*").nameNot("<unknown>").l
    .filter(call => spans.isEmpty || nodeInSpans(call, spans))
  val targetMethod = resultJson(
    "target_method",
    Option(m.name).getOrElse(""),
    fileName(m),
    line(m),
    lineEnd(m),
    Option(m.name).getOrElse(""),
    "",
    "",
    Option(m.code).getOrElse(""),
    List(),
    List(),
    // The target method is only an identity/source anchor. Source variables,
    // calls, writes, and their contracts are emitted as separate typed facts;
    // attaching methodDeps here would reintroduce compiler-generated locals.
    List(),
    Option(m.fullName).getOrElse(""),
    Option(m.signature).getOrElse("")
  )
  val targetCalls = nonOperatorCalls.map { c =>
    resultJson(
      "target_call",
      Option(c.name).getOrElse(""),
      fileName(m),
      line(c),
      lineEnd(c),
      Option(m.name).getOrElse(""),
      "",
      Option(c.name).getOrElse(""),
      Option(c.code).getOrElse(""),
      args(c),
      controlContext(c),
      // Arguments are already emitted structurally in the arguments field.
      // The compact initial contract only needs how the call result is consumed.
      callResultUsageDeps(c),
      Option(c.methodFullName).getOrElse(""),
      ""
    )
  }
  val slicedAssignments = m.call.nameExact("<operator>.assignment").l
    .filter(assignment => spans.isEmpty || nodeInSpans(assignment, spans))
  val assignments = slicedAssignments.map { a =>
    val symbols = a.argument.l.sortBy(_.argumentIndex).headOption
      .map(identifiersFor)
      .getOrElse(List[String]())
    resultJson(
      "target_assignment",
      symbols.headOption.getOrElse(""),
      fileName(m),
      line(a),
      lineEnd(a),
      Option(m.name).getOrElse(""),
      "",
      Option(a.name).getOrElse(""),
      Option(a.code).getOrElse(""),
      args(a),
      controlContext(a),
      List(),
      Option(a.methodFullName).getOrElse(""),
      ""
    )
  }
  val slicedUpdates = List(
    "<operator>.postIncrement", "<operator>.preIncrement",
    "<operator>.postDecrement", "<operator>.preDecrement"
  ).flatMap(name => m.call.nameExact(name).l)
    .filter(update => spans.isEmpty || nodeInSpans(update, spans))
  val updates = slicedUpdates.map { update =>
    val symbols = identifiersFor(update)
    resultJson(
      "target_update",
      symbols.headOption.getOrElse(""),
      fileName(m),
      line(update),
      lineEnd(update),
      Option(m.name).getOrElse(""),
      "",
      Option(update.name).getOrElse(""),
      Option(update.code).getOrElse(""),
      args(update),
      controlContext(update),
      List(),
      Option(update.methodFullName).getOrElse(""),
      ""
    )
  }
  val slicedReturns = m.ast.isReturn.l
    .filter(ret => spans.isEmpty || nodeInSpans(ret, spans))
  val returns = slicedReturns.map { ret =>
    resultJson(
      "target_return", Option(m.name).getOrElse(""), fileName(m),
      line(ret), lineEnd(ret), Option(m.name).getOrElse(""), "", "",
      Option(ret.code).getOrElse(""), List(), controlContext(ret),
      semanticDataflowDeps(ret, m), Option(m.fullName).getOrElse(""),
      Option(m.signature).getOrElse("")
    )
  }
  val slicedControls = m.controlStructure.l.filter { control =>
    spans.isEmpty || nodeInSpans(control, spans)
  }
  val controls = slicedControls.map { control =>
    resultJson(
      "target_control", Option(control.controlStructureType).getOrElse(""),
      fileName(m), line(control), lineEnd(control), Option(m.name).getOrElse(""),
      "", "", Option(control.code).getOrElse(""), List(), controlContext(control),
      List(), Option(m.fullName).getOrElse(""), Option(m.signature).getOrElse("")
    )
  }
  val sliceSymbols = (
    nonOperatorCalls.flatMap(identifiersFor) ++
    slicedAssignments.flatMap(identifiersFor) ++
    slicedUpdates.flatMap(identifiersFor) ++
    slicedReturns.flatMap(identifiersFor)
  ).filter(_.nonEmpty).distinct.toSet
  // Declarations are evidence only when their symbol participates in the
  // retained target slice; compiler-generated and unrelated locals disappear.
  val parameterVariables = m.parameter.l
    .filter(parameter => sliceSymbols.contains(Option(parameter.name).getOrElse("")))
    .map { parameter =>
    resultJson(
      "symbol_usage", Option(parameter.name).getOrElse(""), fileName(m),
      line(parameter), lineEnd(parameter), Option(m.name).getOrElse(""), "", "",
      Option(parameter.code).getOrElse(""), List(), List(), List(),
      Option(m.fullName).getOrElse(""), Option(parameter.typeFullName).getOrElse("")
    )
  }
  val localVariables = m.local.l
    .filter(local => sliceSymbols.contains(Option(local.name).getOrElse("")))
    .map { local =>
    resultJson(
      "symbol_usage", Option(local.name).getOrElse(""), fileName(m),
      line(local), lineEnd(local), Option(m.name).getOrElse(""), "", "",
      Option(local.code).getOrElse(""), List(), List(), List(),
      Option(m.fullName).getOrElse(""), Option(local.typeFullName).getOrElse("")
    )
  }
  val variables = parameterVariables ++ localVariables
  val exactCalleeContracts = nonOperatorCalls.flatMap { call =>
    val callFullName = Option(call.methodFullName).getOrElse("")
    val namedCandidates = cpg.method.nameExact(Option(call.name).getOrElse("")).l.filter { candidate =>
      line(candidate) > 0 && !Set("", "<empty>", "<includes>").contains(fileName(candidate))
    }
    val definitionCandidates =
      if (callFullName.nonEmpty && callFullName != "<unknownFullName>")
        namedCandidates.filter { candidate =>
          canonMethodIdentity(Option(candidate.fullName).getOrElse("")) == canonMethodIdentity(callFullName) &&
          line(candidate) > 0
        }
      else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
    val definitions =
      if (definitionCandidates.size == 1) definitionCandidates
      else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
    definitions.map { callee =>
      resultJson(
        "callee_definition",
        Option(call.name).getOrElse(""),
        fileName(callee),
        line(callee),
        // A callee contract is anchored to its declaration line.  Returning
        // the full method range copied complete callees into initial evidence.
        line(callee),
        Option(callee.name).getOrElse(""),
        callFullName,
        Option(call.name).getOrElse(""),
        (
          Option(callee.name).getOrElse("") + " " +
          Option(callee.signature).getOrElse("")
        ).trim,
        List(),
        List(),
        calleeContractDeps(callee, Option(call.name).getOrElse("")),
        Option(callee.fullName).getOrElse(""),
        Option(callee.signature).getOrElse("")
      )
    }
  }
  // Initial behavior context is a compact projection: exact target calls,
  // source declarations/writes, and only uniquely resolved callee contracts.
  // Candidate overloads, siblings, callers, types, and deep dataflow are lazy
  // get_behavior_evidence queries bound to an LLM proof obligation.
  (List(targetMethod) ++ targetCalls ++ assignments ++ updates ++ returns ++ controls ++ variables ++ exactCalleeContracts).distinct
}

def calleeContractDeps(
  callee: io.shiftleft.codepropertygraph.generated.nodes.Method,
  callName: String
): List[String] = {
  val returns = callee.ast.isReturn.l
  val assignments = callee.call.nameExact("<operator>.assignment").l
  val returnSymbols = returns.flatMap(identifiersFor).distinct
  val externallyVisible = assignments.filter(isExternalStateWrite)
  var demanded = (
    returnSymbols ++ externallyVisible.flatMap(assignmentRhsSymbols)
  ).filter(_.nonEmpty).toSet
  var selected = externallyVisible.map(_.id).toSet
  var changed = true
  while (changed) {
    changed = false
    assignments.sortBy(line).reverse.foreach { assignment =>
      val defined = assignmentDefinedSymbols(assignment).toSet
      if (!selected.contains(assignment.id) && defined.intersect(demanded).nonEmpty) {
        selected = selected + assignment.id
        demanded = demanded ++ assignmentRhsSymbols(assignment)
        changed = true
      }
    }
  }
  val relevantParameters = callee.parameter.l.filter { parameter =>
    demanded.contains(Option(parameter.name).getOrElse(""))
  }
  (
    relevantParameters.map { parameter =>
      contractDepJson(
        "parameter", Option(parameter.name).getOrElse(""), line(parameter),
        Option(parameter.code).getOrElse(""), List()
      )
    } ++
    returns.map { ret =>
      contractDepJson(
        "callee_return", callName, line(ret), Option(ret.code).getOrElse(""),
        controlContext(ret)
      )
    } ++
    assignments.filter(assignment => selected.contains(assignment.id)).map { assignment =>
      contractDepJson(
        "callee_assignment", assignmentDefinedSymbols(assignment).headOption.getOrElse(""),
        line(assignment), Option(assignment.code).getOrElse(""), controlContext(assignment)
      )
    }
  ).distinct.take(48)
}

def assignmentDefinedSymbols(
  assignment: io.shiftleft.codepropertygraph.generated.nodes.Call
): List[String] = {
  assignment.argument.l.sortBy(_.argumentIndex).headOption
    .map(identifiersFor).getOrElse(List[String]()).distinct
}

def assignmentRhsSymbols(
  assignment: io.shiftleft.codepropertygraph.generated.nodes.Call
): List[String] = {
  assignment.argument.l.sortBy(_.argumentIndex).drop(1)
    .flatMap(identifiersFor).distinct
}

def isExternalStateWrite(
  assignment: io.shiftleft.codepropertygraph.generated.nodes.Call
): Boolean = {
  val lhs = assignment.argument.l.sortBy(_.argumentIndex).headOption
    .map(node => Option(node.code).getOrElse("")).getOrElse("")
  lhs.contains("->") || lhs.contains(".") || lhs.contains("[") || lhs.trim.startsWith("*")
}

def contractDepJson(
  kind: String,
  symbol: String,
  lineStart: Int,
  code: String,
  controls: List[String]
): String = {
  val controlsJson = controls.take(6).mkString("[", ",", "]")
  s"""{"kind":"${esc(kind)}","symbol":"${esc(symbol)}","line":$lineStart,"code":"${esc(code)}","control_context":$controlsJson}"""
}

def callResultUsageDeps(c: io.shiftleft.codepropertygraph.generated.nodes.Call): List[String] = {
  val parentOperation = c.astParent match {
    case parent: io.shiftleft.codepropertygraph.generated.nodes.Call =>
      List(depJson(
        "call_result_parent_operation",
        Option(parent.name).getOrElse(""),
        line(parent),
        Option(parent.code).getOrElse("")
      ))
    case _ => List[String]()
  }
  parentOperation
}

def semanticDataflowDeps(
  n: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
  m: io.shiftleft.codepropertygraph.generated.nodes.Method
): List[String] = {
  n match {
    case sink: io.shiftleft.codepropertygraph.generated.nodes.CfgNode =>
      scala.util.Try {
        sink.start.reachableByFlows(m.parameter).l.take(12).map { flow =>
          val elements = flow.elements.take(24)
          val first = elements.headOption
          val symbol = first
            .flatMap(node => identifiersFor(node).headOption)
            .getOrElse(first.map(node => Option(node.code).getOrElse("")).getOrElse(""))
          depJson(
            "semantic_dataflow_path",
            symbol,
            first.map(line).getOrElse(-1),
            elements.map(node => Option(node.code).getOrElse("")).filter(_.nonEmpty).mkString(" -> ")
          )
        }
      }.getOrElse(List[String]())
    case _ => List[String]()
  }
}

def callerResults(names: List[String], limit: Int): List[String] = {
  names.flatMap { name =>
    cpg.call.nameExact(name).l
      .sortBy(c => (fileName(c.method), line(c)))
      .take(limit)
      .map { c =>
        val m = c.method
        resultJson(
          "caller_context",
          name,
          fileName(m),
          line(c),
          lineEnd(c),
          Option(m.name).getOrElse(""),
          Option(m.name).getOrElse(""),
          name,
          Option(c.code).getOrElse(""),
          args(c),
          controlContext(c),
          callResultUsageDeps(c),
          Option(m.fullName).getOrElse(""),
          Option(m.signature).getOrElse("")
        )
      }
  }.take(limit)
}

def calleeResults(names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, limit: Int): List[String] = {
  val defs = names.flatMap { name =>
    cpg.method.nameExact(name).l
      .sortBy(m => (fileName(m), line(m)))
      .take(limit)
      .map { m =>
        resultJson(
          "callee_definition",
          name,
          fileName(m),
          line(m),
          lineEnd(m),
          Option(m.name).getOrElse(""),
          "",
          name,
          Option(m.code).getOrElse(""),
          List(),
          List(),
          methodDeps(m).take(32),
          Option(m.fullName).getOrElse(""),
          Option(m.signature).getOrElse("")
        )
      }
  }
  val callSites = targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { m =>
    m.call.l
      .filter(c => names.isEmpty || names.contains(Option(c.name).getOrElse("")))
      .take(limit)
      .map { c =>
        resultJson(
          "call_argument_flow",
          Option(c.name).getOrElse(""),
          fileName(m),
          line(c),
          lineEnd(c),
          Option(m.name).getOrElse(""),
          Option(m.name).getOrElse(""),
          Option(c.name).getOrElse(""),
          Option(c.code).getOrElse(""),
          args(c),
          controlContext(c),
          argumentDeps(c, m).take(32),
          Option(c.methodFullName).getOrElse(""),
          ""
        )
      }
  }
  (defs ++ callSites).take(limit)
}

def exactTargetCalleeResults(
  names: List[String], sourcePath: String, functionName: String,
  functionSignature: String, functionStartLine: Int, limit: Int
): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { target =>
    target.call.nameNot("<operator>.*").nameNot("<unknown>").l
      .filter(call => names.isEmpty || names.exists(name => symbolMatches(Option(call.name).getOrElse(""), name)))
      .flatMap { call =>
        val callFullName = Option(call.methodFullName).getOrElse("")
        val callName = Option(call.name).getOrElse("")
        val namedCandidates = cpg.method.l.filter { candidate =>
          line(candidate) > 0 &&
          !Set("", "<empty>", "<includes>").contains(fileName(candidate)) &&
          (
            symbolMatches(Option(candidate.name).getOrElse(""), callName) ||
            symbolMatches(Option(candidate.fullName).getOrElse(""), callName)
          )
        }
        val fullNameMatches =
          if (callFullName.nonEmpty && callFullName != "<unknownFullName>")
            namedCandidates.filter { candidate =>
              canonCallableIdentity(Option(candidate.fullName).getOrElse("")) ==
                canonCallableIdentity(callFullName)
            }
          else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
        val exact =
          if (fullNameMatches.size == 1) fullNameMatches
          else if (namedCandidates.size == 1) namedCandidates
          else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
        val contracts = exact.map { callee =>
          resultJson(
            "callee_definition", Option(call.name).getOrElse(""), fileName(callee),
            line(callee), lineEnd(callee), Option(callee.name).getOrElse(""),
            callFullName, Option(call.name).getOrElse(""), Option(callee.code).getOrElse(""),
            List(), List(),
            callee.parameter.l.map { parameter =>
              contractDepJson("parameter", Option(parameter.name).getOrElse(""), line(parameter), Option(parameter.code).getOrElse(""), List())
            } ++ callee.ast.isReturn.l.map { ret =>
              contractDepJson("callee_return", Option(call.name).getOrElse(""), line(ret), Option(ret.code).getOrElse(""), controlContext(ret))
            } ++ callee.call.nameExact("<operator>.assignment").l.map { assignment =>
              contractDepJson("callee_assignment", identifiersFor(assignment).headOption.getOrElse(""), line(assignment), Option(assignment.code).getOrElse(""), controlContext(assignment))
            },
            Option(callee.fullName).getOrElse(""), Option(callee.signature).getOrElse("")
          )
        }
        val candidates =
          if (contracts.nonEmpty) List[String]()
          else namedCandidates.sortBy(candidate => (fileName(candidate), line(candidate))).take(4).map { candidate =>
            resultJson(
              "callee_candidate", callName, fileName(candidate), line(candidate),
              lineEnd(candidate), Option(candidate.name).getOrElse(""), callFullName,
              callName, Option(candidate.code).getOrElse(""), List(), List(),
              methodDeps(candidate).take(24), Option(candidate.fullName).getOrElse(""),
              Option(candidate.signature).getOrElse("")
            )
          }
        contracts ++ candidates
      }
  }.distinct.take(limit)
}

def targetCallArgumentResults(
  names: List[String], sourcePath: String, functionName: String,
  functionSignature: String, functionStartLine: Int, limit: Int
): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { target =>
    target.call.nameNot("<operator>.*").nameNot("<unknown>").l
      .filter(call => names.isEmpty || names.exists(name => symbolMatches(Option(call.name).getOrElse(""), name)))
      .sortBy(line)
      .take(limit)
      .map { call =>
        resultJson(
          "call_argument_flow", Option(call.name).getOrElse(""), fileName(target),
          line(call), lineEnd(call), Option(target.name).getOrElse(""),
          Option(target.fullName).getOrElse(""), Option(call.name).getOrElse(""),
          Option(call.code).getOrElse(""), args(call), controlContext(call),
          argumentDeps(call, target).take(32), Option(call.methodFullName).getOrElse(""), ""
        )
      }
  }.distinct.take(limit)
}

def siblingImplementationResults(
  names: List[String], sourcePath: String, functionName: String,
  functionSignature: String, functionStartLine: Int, limit: Int
): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { target =>
    target.call.nameNot("<operator>.*").nameNot("<unknown>").l
      .filter(call => names.isEmpty || names.contains(Option(call.name).getOrElse("")))
      .flatMap { call =>
        val callFullName = Option(call.methodFullName).getOrElse("")
        if (callFullName.isEmpty || callFullName == "<unknownFullName>") List[String]()
        else cpg.call.nameExact(Option(call.name).getOrElse("")).l
          .filter(other =>
            other.id != call.id && other.method != null && line(other) > 0 &&
            canonMethodIdentity(Option(other.methodFullName).getOrElse("")) == canonMethodIdentity(callFullName)
          )
          .sortBy(other => (fileName(other.method), line(other)))
          .map { other =>
            val owner = other.method
            resultJson(
              "method_definition", Option(call.name).getOrElse(""), fileName(owner),
              line(owner), lineEnd(owner), Option(owner.name).getOrElse(""),
              callFullName, Option(call.name).getOrElse(""), Option(owner.code).getOrElse(""),
              args(other), controlContext(other),
              depJson("sibling_callsite", Option(other.name).getOrElse(""), line(other), Option(other.code).getOrElse("")) :: callResultUsageDeps(other),
              Option(owner.fullName).getOrElse(""), Option(owner.signature).getOrElse("")
            )
          }
      }
  }.distinct.take(limit)
}

def symbolUsageResults(names: List[String], limit: Int): List[String] = {
  names.flatMap { name =>
    val calls = cpg.call.nameExact(name).l.take(limit).map { c =>
      resultJson(
        "symbol_usage",
        name,
        fileName(c.method),
        line(c),
        lineEnd(c),
        Option(c.method.name).getOrElse(""),
        Option(c.method.name).getOrElse(""),
        Option(c.name).getOrElse(""),
        Option(c.code).getOrElse(""),
        args(c),
        controlContext(c),
        argumentDeps(c, c.method).take(32),
        Option(c.methodFullName).getOrElse(""),
        ""
      )
    }
    val identifiers = cpg.identifier.nameExact(name).l.take(limit).map { i =>
      val m = i.method
      resultJson(
        "symbol_usage",
        name,
        fileName(m),
        line(i),
        lineEnd(i),
        Option(m.name).getOrElse(""),
        Option(m.name).getOrElse(""),
        "",
        Option(i.code).getOrElse(""),
        List(),
        controlContext(i),
        reachingDefs(i, m, List(name)).take(32),
        Option(m.fullName).getOrElse(""),
        Option(m.signature).getOrElse("")
      )
    }
    calls ++ identifiers
  }.sortBy(raw => jsonInt(raw, "line")).take(limit)
}

def typeOrMacroResults(names: List[String], limit: Int): List[String] = {
  names.flatMap { name =>
    val types = cpg.typeDecl.l
      .filter(t => symbolMatches(Option(t.name).getOrElse(""), name) || symbolMatches(Option(t.fullName).getOrElse(""), name))
      .take(limit).map { t =>
      resultJson(
        "type_definition",
        name,
        fileName(t),
        line(t),
        lineEnd(t),
        Option(t.name).getOrElse(""),
        "",
        "",
        Option(t.code).getOrElse(""),
        List(),
        List(),
        List(),
        Option(t.fullName).getOrElse(""),
        ""
      )
    }
    val members = cpg.member.l
      .filter(member => symbolMatches(Option(member.name).getOrElse(""), name))
      .filter(member => line(member) > 0)
      .take(limit).map { member =>
      val owner = member.astParent match {
        case value: io.shiftleft.codepropertygraph.generated.nodes.TypeDecl => Some(value)
        case _ => None
      }
      val ownerFullName = owner.map(value => Option(value.fullName).getOrElse("")).getOrElse("")
      resultJson(
        "type_definition",
        name,
        owner.map(fileName).getOrElse(fileName(member)),
        line(member),
        lineEnd(member),
        Option(member.name).getOrElse(""),
        "",
        "",
        Option(member.code).getOrElse(""),
        List(),
        List(),
        List(),
        List(ownerFullName, Option(member.name).getOrElse("")).filter(_.nonEmpty).mkString("::"),
        Option(member.typeFullName).getOrElse("")
      )
    }
    val methods = cpg.method.l
      .filter(m => symbolMatches(Option(m.name).getOrElse(""), name) || symbolMatches(Option(m.fullName).getOrElse(""), name))
      .take(limit).map { m =>
      resultJson(
        "method_definition",
        name,
        fileName(m),
        line(m),
        lineEnd(m),
        Option(m.name).getOrElse(""),
        "",
        "",
        Option(m.code).getOrElse(""),
        List(),
        List(),
        methodDeps(m).take(32),
        Option(m.fullName).getOrElse(""),
        Option(m.signature).getOrElse("")
      )
    }
    types ++ members ++ methods
  }.take(limit)
}

def controlDataResults(names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { m =>
    val symbols = if (names.nonEmpty) names else identifiersFor(m).take(24)
    val calls = m.call.l
      .filter(c => intersects(identifiersFor(c), symbols) || symbols.contains(Option(c.name).getOrElse("")))
      .take(limit)
      .map { c =>
        resultJson(
          "control_data_dependency",
          symbols.find(s => identifiersFor(c).contains(s)).getOrElse(Option(c.name).getOrElse("")),
          fileName(m),
          line(c),
          lineEnd(c),
          Option(m.name).getOrElse(""),
          "",
          Option(c.name).getOrElse(""),
          Option(c.code).getOrElse(""),
          args(c),
          controlContext(c),
              (argumentDeps(c, m) ++ reachingDefs(c, m, symbols) ++ interproceduralDeps(m, symbols)).take(64),
          Option(c.methodFullName).getOrElse(""),
          ""
        )
      }
    val returns = m.ast.isReturn.l
      .filter(r => intersects(identifiersFor(r), symbols))
      .take(limit)
      .map { r =>
        resultJson(
          "control_data_dependency",
          symbols.find(s => identifiersFor(r).contains(s)).getOrElse(Option(m.name).getOrElse("")),
          fileName(m),
          line(r),
          lineEnd(r),
          Option(m.name).getOrElse(""),
          "",
          "",
          Option(r.code).getOrElse(""),
          List(),
          controlContext(r),
          (reachingDefs(r, m, symbols) ++ interproceduralDeps(m, symbols)).take(64),
          Option(m.fullName).getOrElse(""),
          Option(m.signature).getOrElse("")
        )
      }
    calls ++ returns
  }.take(limit)
}

def variableBehaviorResults(names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { m =>
    val assignments = m.call.nameExact("<operator>.assignment").l
      .flatMap { c =>
        val hits = identifiersFor(c).filter(names.contains).distinct
        hits.map { symbol =>
          resultJson(
            "assignment",
            symbol,
            fileName(m),
            line(c),
            lineEnd(c),
            Option(m.name).getOrElse(""),
            "",
            Option(c.name).getOrElse(""),
            Option(c.code).getOrElse(""),
            args(c),
            controlContext(c),
            reachingDefs(c, m, List(symbol)).take(32),
            Option(m.fullName).getOrElse(""),
            Option(m.signature).getOrElse("")
          )
        }
      }
    val usages = names.flatMap { symbol =>
      m.ast.isIdentifier.nameExact(symbol).l
        .take(limit)
        .map { i =>
          resultJson(
            "symbol_usage",
            symbol,
            fileName(m),
            line(i),
            lineEnd(i),
            Option(m.name).getOrElse(""),
            "",
            "",
            Option(i.code).getOrElse(""),
            List(),
            controlContext(i),
            reachingDefs(i, m, List(symbol)).take(32),
            Option(m.fullName).getOrElse(""),
            Option(m.signature).getOrElse("")
          )
        }
    }
    (assignments ++ usages).distinct.take(limit)
  }.take(limit)
}

def projectValueUsageResults(
  names: List[String], sourcePath: String, functionName: String,
  functionSignature: String, functionStartLine: Int, limit: Int
): List[String] = {
  val targets = targetMethods(sourcePath, functionName, functionSignature, functionStartLine)
  val targetFiles = targets.map(fileName).filter(_.nonEmpty).toSet
  val targetOwners = targets.map(methodOwner).filter(_.nonEmpty).toSet
  val requestedSymbols = names.filter(_.nonEmpty).distinct
  val perSymbolLimit = math.max(1, math.ceil(limit.toDouble / requestedSymbols.size.max(1)).toInt)
  requestedSymbols.flatMap { symbol =>
    val identifiers = cpg.identifier.nameExact(symbol).l
      .filter(identifier => line(identifier) > 0 && identifier.method != null)
      .sortBy { identifier =>
        val owner = methodOwner(identifier.method)
        val file = fileName(identifier.method)
        val locality =
          if (targetOwners.contains(owner)) 0
          else if (targetFiles.contains(file) || strictSourceMatch(file, sourcePath)) 1
          else 2
        (locality, file, line(identifier))
      }
      .take(perSymbolLimit)
      .map { identifier =>
        val owner = identifier.method
        resultJson(
          "symbol_usage", symbol, fileName(owner), line(identifier), lineEnd(identifier),
          Option(owner.name).getOrElse(""), Option(owner.fullName).getOrElse(""), "",
          Option(identifier.code).getOrElse(""), List(), controlContext(identifier),
          reachingDefs(identifier, owner, List(symbol)).take(32),
          Option(owner.fullName).getOrElse(""), Option(owner.signature).getOrElse("")
        )
      }
    val fields = cpg.fieldIdentifier.l
      .filter(field => symbolMatches(Option(field.canonicalName).getOrElse(""), symbol))
      .filter(field => line(field) > 0 && field.method != null)
      .sortBy { field =>
        val owner = field.method
        val ownerName = methodOwner(owner)
        val file = fileName(owner)
        val locality =
          if (targetOwners.contains(ownerName)) 0
          else if (targetFiles.contains(file) || strictSourceMatch(file, sourcePath)) 1
          else 2
        (locality, file, line(field))
      }
      .take(perSymbolLimit)
      .map { field =>
        val owner = field.method
        resultJson(
          "symbol_usage", symbol, fileName(owner), line(field), lineEnd(field),
          Option(owner.name).getOrElse(""), Option(owner.fullName).getOrElse(""), "",
          Option(field.code).getOrElse(""), List(), controlContext(field),
          reachingDefs(field, owner, List(symbol)).take(32),
          Option(owner.fullName).getOrElse(""), Option(owner.signature).getOrElse("")
        )
      }
    val calls = cpg.call.l
      .filter(call => line(call) > 0 && call.method != null && identifiersFor(call).contains(symbol))
      .sortBy { call =>
        val owner = methodOwner(call.method)
        val file = fileName(call.method)
        val locality =
          if (targetOwners.contains(owner)) 0
          else if (targetFiles.contains(file) || strictSourceMatch(file, sourcePath)) 1
          else 2
        (locality, file, line(call))
      }
      .take(perSymbolLimit)
      .map { call =>
        val owner = call.method
        resultJson(
          "control_data_dependency", symbol, fileName(owner), line(call), lineEnd(call),
          Option(owner.name).getOrElse(""), Option(owner.fullName).getOrElse(""),
          Option(call.name).getOrElse(""), Option(call.code).getOrElse(""), args(call),
          controlContext(call), argumentDeps(call, owner).take(32),
          Option(call.methodFullName).getOrElse(""), Option(owner.signature).getOrElse("")
        )
      }
    (identifiers ++ fields ++ calls).distinct.take(perSymbolLimit)
  }.distinct.take(limit)
}

def inferredTypeNames(
  names: List[String], sourcePath: String, functionName: String,
  functionSignature: String, functionStartLine: Int
): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { method =>
    method.ast.isIdentifier.l
      .filter(identifier => names.exists(name => symbolMatches(Option(identifier.name).getOrElse(""), name)))
      .map(identifier => typeLeaf(Option(identifier.typeFullName).getOrElse("")))
  }.filter(_.nonEmpty).distinct.take(24)
}

def methodOwner(method: io.shiftleft.codepropertygraph.generated.nodes.Method): String = {
  val identity = canonCallableIdentity(Option(method.fullName).getOrElse(""))
  identity.split("::").dropRight(1).mkString("::")
}

def typeLeaf(value: String): String = {
  val noPointer = Option(value).getOrElse("")
    .replace("*", "").replace("&", "").replace("const", "").trim
  noPointer.split("::").lastOption.getOrElse(noPointer)
}

def targetRegionResults(names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int): List[String] = {
  targetMethods(sourcePath, functionName, functionSignature, functionStartLine).flatMap { m =>
    val symbols = if (names.nonEmpty) names else identifiersFor(m).take(24)
    val controls = m.controlStructure.l.filter(c => spans.isEmpty || nodeInSpans(c, spans)).take(limit).map { c =>
      resultJson(
        "target_region",
        Option(m.name).getOrElse(""),
        fileName(m),
        line(c),
        lineEnd(c),
        Option(m.name).getOrElse(""),
        "",
        "",
        Option(c.code).getOrElse(""),
        List(),
        controlContext(c),
        List(),
        Option(m.fullName).getOrElse(""),
        Option(m.signature).getOrElse("")
      )
    }
    val ops = m.call.l
      .filter(c => spans.isEmpty || nodeInSpans(c, spans))
      .filter(c => symbols.isEmpty || intersects(identifiersFor(c), symbols)).take(limit).map { c =>
      resultJson(
        "target_region",
        Option(c.name).getOrElse(Option(m.name).getOrElse("")),
        fileName(m),
        line(c),
        lineEnd(c),
        Option(m.name).getOrElse(""),
        "",
        Option(c.name).getOrElse(""),
        Option(c.code).getOrElse(""),
        args(c),
        controlContext(c),
        argumentDeps(c, m).take(32),
        Option(c.methodFullName).getOrElse(""),
        ""
      )
    }
    controls ++ ops
  }.take(limit)
}

def semanticContextBundle(names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int): List[String] = {
  val leaf = canonMethodIdentity(functionName).split("::").lastOption.getOrElse(functionName)
  val symbolBudget = names.filter(_.nonEmpty).distinct.take(24)
  // Keep a structural quota for each evidence family.  Concatenating six
  // `limit`-sized lists and truncating at the end used to let target-local
  // operations consume the complete result, hiding caller/callee contracts.
  val familyBudget = math.max(2, limit / 6)
  val target = targetRegionResults(symbolBudget, sourcePath, functionName, functionSignature, functionStartLine, spans, familyBudget)
  val dependencies = controlDataResults(symbolBudget, sourcePath, functionName, functionSignature, functionStartLine, spans, familyBudget)
  val callers = callerResults(List(leaf).filter(_.nonEmpty), familyBudget)
  val targetCalleeNames = targetMethods(sourcePath, functionName, functionSignature, functionStartLine)
    .flatMap(_.call.name.l)
    .filter(_.nonEmpty)
    .distinct
    .take(familyBudget)
  // Callee names come only from call nodes in the exact target method.  This
  // avoids broad identifier searches while still retrieving definitions and
  // argument-flow evidence for the concrete calls under repair.
  val callees = calleeResults(targetCalleeNames, sourcePath, functionName, functionSignature, functionStartLine, familyBudget)
  val usages = symbolUsageResults(symbolBudget, familyBudget)
  val definitions = typeOrMacroResults(symbolBudget, familyBudget)
  (target ++ dependencies ++ callers ++ callees ++ usages ++ definitions).distinct.take(limit)
}

def behaviorEvidence(relations: List[String], names: List[String], sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int, spans: List[(String, Int, Int)], limit: Int): List[String] = {
  val requested = relations.map(_.toUpperCase).distinct
  val symbols = names.filter(_.nonEmpty).distinct.take(24)
  val leaf = canonMethodIdentity(functionName).split("::").lastOption.getOrElse(functionName)
  def wants(values: String*): Boolean = values.exists(requested.contains)
  val families = List(
    wants("CALLER_RESULT_USE", "CALLER_BRANCH_ON_RESULT", "RETURN_VALUE_FLOW", "ERROR_PROPAGATION"),
    wants("CALLEE_CONTRACT", "CALL_ARGUMENT_MAPPING", "CALL_RESULT_CONTRACT", "ERROR_PROPAGATION"),
    wants("REACHING_DEFINITIONS", "VALUE_USES", "FIELD_READ_WRITE", "STATE_TRANSITIONS", "ALIAS_OR_REFERENCE_FLOW"),
    wants("CONTROLLING_PREDICATES", "BRANCH_REACHABILITY", "EARLY_RETURN_CONDITIONS", "ALTERNATE_PATH_STATE"),
    wants("TYPE_DEFINITION", "ENUM_OR_SENTINEL_VALUES", "OVERLOAD_SET", "TEMPLATE_SPECIALIZATION", "CONVERSION_OPERATORS"),
    wants("SIBLING_BRANCH", "SIBLING_IMPLEMENTATION", "SAME_TYPE_OPERATION", "PARALLEL_ERROR_HANDLING")
  ).count(identity).max(1)
  val familyBudget = math.max(2, limit / families)
  val callerEvidence =
    if (wants("CALLER_RESULT_USE", "CALLER_BRANCH_ON_RESULT", "RETURN_VALUE_FLOW", "ERROR_PROPAGATION"))
      callerResults(List(leaf).filter(_.nonEmpty), familyBudget)
    else List[String]()
  val calleeNames = targetMethods(sourcePath, functionName, functionSignature, functionStartLine)
    .flatMap(_.call.name.l)
    .filter(name => name.nonEmpty && (symbols.isEmpty || symbols.exists(symbol => symbolMatches(name, symbol))))
    .distinct
    .take(24)
  val calleeEvidence =
    if (wants("CALLEE_CONTRACT", "CALL_ARGUMENT_MAPPING", "CALL_RESULT_CONTRACT", "ERROR_PROPAGATION"))
      if (calleeNames.nonEmpty)
        (
          exactTargetCalleeResults(calleeNames, sourcePath, functionName, functionSignature, functionStartLine, familyBudget) ++
          targetCallArgumentResults(calleeNames, sourcePath, functionName, functionSignature, functionStartLine, familyBudget)
        ).distinct.take(familyBudget * 2)
      else List[String]()
    else List[String]()
  val targetDataEvidence =
    if (wants("REACHING_DEFINITIONS", "FIELD_READ_WRITE", "STATE_TRANSITIONS", "ALIAS_OR_REFERENCE_FLOW"))
      (
        controlDataResults(symbols, sourcePath, functionName, functionSignature, functionStartLine, spans, familyBudget) ++
        variableBehaviorResults(symbols, sourcePath, functionName, functionSignature, functionStartLine, spans, familyBudget)
      ).distinct.take(familyBudget * 2)
    else List[String]()
  val valueUseEvidence =
    if (wants("VALUE_USES"))
      projectValueUsageResults(symbols, sourcePath, functionName, functionSignature, functionStartLine, familyBudget)
    else List[String]()
  val controlEvidence =
    if (wants("CONTROLLING_PREDICATES", "BRANCH_REACHABILITY", "EARLY_RETURN_CONDITIONS", "ALTERNATE_PATH_STATE"))
      targetRegionResults(symbols, sourcePath, functionName, functionSignature, functionStartLine, spans, familyBudget)
    else List[String]()
  val typeEvidence =
    if (wants("TYPE_DEFINITION", "ENUM_OR_SENTINEL_VALUES", "OVERLOAD_SET", "TEMPLATE_SPECIALIZATION", "CONVERSION_OPERATORS"))
      typeOrMacroResults(
        (symbols ++ inferredTypeNames(symbols, sourcePath, functionName, functionSignature, functionStartLine)).distinct,
        familyBudget
      )
    else List[String]()
  val siblingEvidence =
    if (wants("SIBLING_IMPLEMENTATION"))
      siblingImplementationResults(symbols, sourcePath, functionName, functionSignature, functionStartLine, familyBudget)
    else if (wants("SIBLING_BRANCH", "SAME_TYPE_OPERATION", "PARALLEL_ERROR_HANDLING"))
      symbolUsageResults(symbols, familyBudget)
    else List[String]()
  (callerEvidence ++ calleeEvidence ++ targetDataEvidence ++ valueUseEvidence ++ controlEvidence ++ typeEvidence ++ siblingEvidence)
    .distinct
    .take(limit)
}

def searchResults(names: List[String], kinds: List[String], limit: Int): List[String] = {
  val queryNames = names.filter(_.length >= 2).take(24)
  if (queryNames.isEmpty) {
    return List[String]()
  }
  val kindText = kinds.mkString(" ").toLowerCase
  def wants(value: String): Boolean = kinds.isEmpty || kindText.contains(value)
  val bySymbol = symbolUsageResults(queryNames, limit)
  val methods =
    if (wants("method") || wants("callee") || wants("caller") || wants("definition")) {
      cpg.method
        .filter(m => queryNames.exists(q => containsFold(m.name, q) || containsFold(m.fullName, q) || containsFold(m.code, q)))
        .l
        .sortBy(m => (fileName(m), line(m)))
        .take(limit)
        .map { m =>
          resultJson(
            "method_definition",
            Option(m.name).getOrElse(""),
            fileName(m),
            line(m),
            lineEnd(m),
            Option(m.name).getOrElse(""),
            "",
            "",
            Option(m.code).getOrElse(""),
            List(),
            List(),
            methodDeps(m).take(32),
            Option(m.fullName).getOrElse(""),
            Option(m.signature).getOrElse("")
          )
        }
    } else List[String]()
  val types =
    if (wants("type") || wants("macro") || wants("enum") || wants("definition")) {
      cpg.typeDecl
        .filter(t => queryNames.exists(q => containsFold(t.name, q) || containsFold(t.fullName, q) || containsFold(t.code, q)))
        .l
        .sortBy(t => (fileName(t), line(t)))
        .take(limit)
        .map { t =>
          resultJson(
            "type_definition",
            Option(t.name).getOrElse(""),
            fileName(t),
            line(t),
            lineEnd(t),
            Option(t.name).getOrElse(""),
            "",
            "",
            Option(t.code).getOrElse(""),
            List(),
            List(),
            List(),
            Option(t.fullName).getOrElse(""),
            ""
          )
        }
    } else List[String]()
  val calls =
    if (wants("call") || wants("usage") || wants("argument") || wants("flow")) {
      cpg.call
        .filter(c => queryNames.exists(q => containsFold(c.name, q) || containsFold(c.code, q) || identifiersFor(c).exists(v => containsFold(v, q))))
        .l
        .sortBy(c => (fileName(c.method), line(c)))
        .take(limit)
        .map { c =>
          val m = c.method
          resultJson(
            "symbol_usage",
            Option(c.name).getOrElse(""),
            fileName(m),
            line(c),
            lineEnd(c),
            Option(m.name).getOrElse(""),
            Option(m.name).getOrElse(""),
            Option(c.name).getOrElse(""),
            Option(c.code).getOrElse(""),
            args(c),
            controlContext(c),
            argumentDeps(c, m).take(32),
            Option(c.methodFullName).getOrElse(""),
            ""
          )
        }
    } else List[String]()
  val controls =
    if (wants("control") || wants("predicate") || wants("condition") || wants("branch")) {
      cpg.controlStructure
        .filter(c => queryNames.exists(q => containsFold(c.code, q) || containsFold(c.controlStructureType, q)))
        .l
        .sortBy(c => (fileName(c), line(c)))
        .take(limit)
        .map { c =>
          val m = c.method
          resultJson(
            "control_data_dependency",
            Option(m.name).getOrElse(""),
            fileName(m),
            line(c),
            lineEnd(c),
            Option(m.name).getOrElse(""),
            "",
            "",
            Option(c.code).getOrElse(""),
            List(),
            controlContext(c),
            reachingDefs(c, m, queryNames).take(32),
            Option(m.fullName).getOrElse(""),
            Option(m.signature).getOrElse("")
          )
        }
    } else List[String]()
  (bySymbol ++ methods ++ types ++ calls ++ controls).distinct.take(limit)
}

def targetMethods(sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int): List[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
  selectTargetMethods(sourcePath, functionName, functionSignature, functionStartLine)._1
}

def selectTargetMethods(sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int): (List[io.shiftleft.codepropertygraph.generated.nodes.Method], List[String]) = {
  val sourceNorm = normalizePath(sourcePath)
  val requested = canonMethodIdentity(functionName)
  val leaf = requested.split("::").lastOption.getOrElse(requested)
  val byLeaf =
    if (leaf.nonEmpty) cpg.method.nameExact(leaf).l
    else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
  val scoped = byLeaf.filter { m =>
    val full = canonMethodIdentity(Option(m.fullName).getOrElse(""))
    requested.isEmpty || !requested.contains("::") || full.contains(requested)
  }
  val byIdentity = if (scoped.nonEmpty) scoped else byLeaf
  val signatureNorm = canonMethodIdentity(functionSignature)
  val signatureMatched = byIdentity.filter { m =>
    val sig = canonMethodIdentity(Option(m.signature).getOrElse(""))
    val code = canonMethodIdentity(Option(m.code).getOrElse(""))
    signatureNorm.nonEmpty && (sig == signatureNorm || code.contains(signatureNorm))
  }
  val bySignature = if (signatureMatched.nonEmpty) signatureMatched else byIdentity
  val lineMatched = bySignature.filter(m => functionStartLine > 0 && m.lineNumber.exists(_ == functionStartLine))
  val byName = if (lineMatched.nonEmpty) lineMatched else bySignature
  if (sourceNorm.isEmpty) {
    return (byName, List[String]())
  }
  val strict = byName.filter(m => strictSourceMatch(fileName(m), sourceNorm))
  if (strict.nonEmpty) {
    return (strict, List[String]())
  }
  val sourceBase = baseName(sourceNorm)
  val basenameFiles = cpg.method.l
    .map(m => normalizePath(fileName(m)))
    .filter(file => baseName(file) == sourceBase)
    .distinct
  val basenameMatches = byName.filter(m => baseName(fileName(m)) == sourceBase)
  if (basenameMatches.nonEmpty && basenameFiles.size == 1) {
    return (basenameMatches, List("joern_source_match_used_unique_basename_fallback"))
  }
  if (basenameMatches.nonEmpty && basenameFiles.size > 1) {
    return (
      List[io.shiftleft.codepropertygraph.generated.nodes.Method](),
      List("joern_source_match_ambiguous_basename:" + sourceBase)
    )
  }
  (List[io.shiftleft.codepropertygraph.generated.nodes.Method](), List("joern_strict_source_match_failed:" + sourceNorm))
}

def fileMatchUncertainties(sourcePath: String, functionName: String, functionSignature: String, functionStartLine: Int): List[String] = {
  selectTargetMethods(sourcePath, functionName, functionSignature, functionStartLine)._2
}

def canonMethodIdentity(value: String): String = {
  Option(value).getOrElse("")
    .replaceAll("\\s+", "")
    .replaceAll("\\.", "::")
    .replaceAll("<[^<>]*>", "")
}

def canonCallableIdentity(value: String): String = {
  canonMethodIdentity(value)
    .replaceAll("(?<!:):(?!:).*$", "")
    .replaceAll("\\([^()]*\\)$", "")
}

def canonSymbol(value: String): String = {
  val callable = canonCallableIdentity(value)
  callable.split("::").lastOption.getOrElse(callable).toLowerCase
}

def symbolMatches(left: String, right: String): Boolean = {
  val a = canonSymbol(left)
  val b = canonSymbol(right)
  a.nonEmpty && b.nonEmpty && a == b
}

def parseRegionSpans(value: String): List[(String, Int, Int)] = {
  splitParam(value).flatMap { raw =>
    raw.split(",", -1).toList match {
      case id :: start :: end :: _ if id.nonEmpty =>
        for {
          startLine <- scala.util.Try(start.toInt).toOption if startLine > 0
          endLine <- scala.util.Try(end.toInt).toOption
        } yield (id, startLine, endLine.max(startLine))
      case _ => None
    }
  }
}

def filterResultsByRegions(results: List[String], spans: List[(String, Int, Int)], regionIds: List[String]): List[String] = {
  if (regionIds.isEmpty) {
    return results
  }
  if (spans.isEmpty) {
    return List[String]()
  }
  results.filter { raw =>
    val start = jsonInt(raw, "line")
    val endValue = jsonInt(raw, "line_end")
    val end = if (endValue >= start) endValue else start
    start > 0 && spans.exists { case (_, regionStart, regionEnd) =>
      rangesOverlap(start, end, regionStart, regionEnd)
    }
  }
}

def regionUncertainties(
  regionIds: List[String],
  spans: List[(String, Int, Int)],
  rawResults: List[String],
  results: List[String]
): List[String] = {
  if (regionIds.isEmpty) {
    return List[String]()
  }
  val matchedIds = spans.map(_._1).distinct
  val missingIds = regionIds.filterNot(matchedIds.contains)
  (if (missingIds.nonEmpty) List("joern_region_ids_not_mapped:" + missingIds.mkString("|")) else List[String]()) ++
    (if (rawResults.nonEmpty && results.isEmpty) List("joern_region_filter_removed_all_results") else List[String]())
}

def rangesOverlap(start: Int, end: Int, otherStart: Int, otherEnd: Int): Boolean = {
  val aEnd = if (end >= start) end else start
  val bEnd = if (otherEnd >= otherStart) otherEnd else otherStart
  start <= bEnd && otherStart <= aEnd
}

def nodeInSpans(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode, spans: List[(String, Int, Int)]): Boolean = {
  val start = line(n)
  val endValue = lineEnd(n)
  val end = if (endValue >= start) endValue else start
  start > 0 && spans.exists { case (_, regionStart, regionEnd) =>
    rangesOverlap(start, end, regionStart, regionEnd)
  }
}

def normalizePath(value: String): String = {
  Option(value).getOrElse("").replace("\\", "/").replaceAll("/+", "/").stripSuffix("/")
}

def baseName(value: String): String = {
  normalizePath(value).split("/").lastOption.getOrElse(normalizePath(value))
}

def strictSourceMatch(file: String, sourcePath: String): Boolean = {
  val f = normalizePath(file)
  val s = normalizePath(sourcePath)
  if (s.isEmpty || f.isEmpty) {
    false
  } else {
    f == s || f.endsWith("/" + s) || s.endsWith("/" + f)
  }
}

def methodDeps(m: io.shiftleft.codepropertygraph.generated.nodes.Method): List[String] = {
  val params = m.parameter.l.take(16).map { p =>
    depJson("parameter", Option(p.name).getOrElse(""), line(p), Option(p.code).getOrElse(""))
  }
  val locals = m.local.l.take(16).map { l =>
    depJson("local", Option(l.name).getOrElse(""), -1, Option(l.code).getOrElse(""))
  }
  params ++ locals
}

def argumentDeps(c: io.shiftleft.codepropertygraph.generated.nodes.Call, m: io.shiftleft.codepropertygraph.generated.nodes.Method): List[String] = {
  c.argument.l.sortBy(_.argumentIndex).take(16).map { arg =>
    depJson("argument_flow", Option(c.name).getOrElse(""), line(arg), Option(arg.code).getOrElse(""))
  }
}

def reachingDefs(
  n: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
  m: io.shiftleft.codepropertygraph.generated.nodes.Method,
  symbols: List[String]
): List[String] = {
  val ln = line(n)
  if (ln <= 0 || symbols.isEmpty) {
    return List[String]()
  }
  val assignments = m.call.name("<operator>.assignment").l
    .filter(a => line(a) > 0 && line(a) != ln)
    .flatMap { a =>
      val lhs = a.argument.l.sortBy(_.argumentIndex).headOption.map(identifiersFor).getOrElse(List())
      val hits = lhs.filter(symbols.contains).distinct
      hits.map(sym => (line(a), sym, Option(a.code).getOrElse("")))
    }
    .distinct
  val backward = assignments
    .filter { case (assignLine, _, _) => assignLine < ln }
    .sortBy { case (assignLine, _, _) => assignLine }
    .takeRight(24)
    .map { case (assignLine, sym, code) => depJson("reaching_definition", sym, assignLine, code) }
  val forward = assignments
    .filter { case (assignLine, _, _) => assignLine > ln }
    .sortBy { case (assignLine, _, _) => assignLine }
    .take(24)
    .map { case (assignLine, sym, code) => depJson("forward_assignment", sym, assignLine, code) }
  backward.takeRight(16) ++ forward.take(16) ++ backward.dropRight(16) ++ forward.drop(16)
}

def interproceduralDeps(
  m: io.shiftleft.codepropertygraph.generated.nodes.Method,
  symbols: List[String]
): List[String] = {
  val methodName = Option(m.name).getOrElse("")
  val callerArguments =
    if (methodName.nonEmpty) {
      cpg.call.nameExact(methodName).l
        .flatMap { call =>
          val caller = call.method
          call.argument.l.sortBy(_.argumentIndex).take(16)
            .filter { arg =>
              val ids = identifiersFor(arg)
              symbols.isEmpty || intersects(ids, symbols) || symbols.exists(sym => containsFold(Option(arg.code).getOrElse(""), sym))
            }
            .map { arg =>
              depJson(
                "interprocedural_caller_argument",
                Option(call.name).getOrElse(methodName),
                line(arg),
                s"${fileName(caller)}:${line(call)} ${Option(arg.code).getOrElse("")}"
              )
            }
        }
        .take(24)
    } else List[String]()
  val calleeReturns = m.call.nameNot("<operator>.*").nameNot("<unknown>").l
    .filter { call =>
      symbols.isEmpty || symbols.contains(Option(call.name).getOrElse("")) || intersects(identifiersFor(call), symbols)
    }
    .flatMap { call =>
      cpg.method.nameExact(Option(call.name).getOrElse("")).l.take(4).flatMap { callee =>
        callee.ast.isReturn.l.take(4).map { ret =>
          depJson(
            "interprocedural_callee_return",
            Option(call.name).getOrElse(""),
            line(ret),
            s"${fileName(callee)}:${line(ret)} ${Option(ret.code).getOrElse("")}"
          )
        }
      }
    }
    .take(24)
  (callerArguments ++ calleeReturns).take(48)
}

def controlContext(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): List[String] = {
  val ln = line(n)
  if (ln <= 0) {
    return List[String]()
  }
  val controls = controlStructuresFor(n)
  scala.util.Try {
    controls
      .filter { c =>
        val start = line(c)
        val end = lineEnd(c)
        val containsNode =
          if (end > start) start <= ln && ln <= end
          else ln == start
        start > 0 && containsNode && c.id != n.id
      }
      .takeRight(6)
      .map { c =>
        s"""{"kind":"${esc(Option(c.controlStructureType).getOrElse(""))}","line":${line(c)},"line_end":${lineEnd(c)},"code":"${esc(Option(c.code).getOrElse(""))}"}"""
      }
  }.getOrElse(List[String]())
}

def controlStructuresFor(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): List[io.shiftleft.codepropertygraph.generated.nodes.ControlStructure] = {
  n match {
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
      c.method.controlStructure.l
    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
      i.method.controlStructure.l
    case c: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure =>
      c.method.controlStructure.l
    case r: io.shiftleft.codepropertygraph.generated.nodes.Return =>
      r.method.controlStructure.l
    case _ =>
      List[io.shiftleft.codepropertygraph.generated.nodes.ControlStructure]()
  }
}

def args(c: io.shiftleft.codepropertygraph.generated.nodes.Call): List[String] = {
  c.argument.l.sortBy(_.argumentIndex).take(16).map(a => Option(a.code).getOrElse(""))
}

def identifiersFor(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): List[String] = {
  (n.ast.isIdentifier.name.l ++ n.ast.isFieldIdentifier.canonicalName.l).distinct
}

def intersects(values: List[String], targets: List[String]): Boolean = {
  values.exists(targets.contains)
}

def containsFold(value: String, query: String): Boolean = {
  Option(value).getOrElse("").toLowerCase.contains(Option(query).getOrElse("").toLowerCase)
}

def fileName(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String = {
  val raw = n match {
    case m: io.shiftleft.codepropertygraph.generated.nodes.Method =>
      Option(m.filename).getOrElse("")
    case t: io.shiftleft.codepropertygraph.generated.nodes.TypeDecl =>
      Option(t.filename).getOrElse("")
    case _ =>
      scala.util.Try(Option(n.getClass.getMethod("filename").invoke(n).asInstanceOf[String]).getOrElse(""))
        .getOrElse("")
  }
  raw.replace("\\", "/")
}

def line(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int = {
  n.lineNumber.getOrElse(-1)
}

def lineEnd(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int = {
  n match {
    case m: io.shiftleft.codepropertygraph.generated.nodes.Method =>
      m.lineNumberEnd.getOrElse(line(n))
    case _ =>
      scala.util.Try(
        n.getClass.getMethod("lineNumberEnd").invoke(n).asInstanceOf[Option[Int]].getOrElse(line(n))
      ).getOrElse(line(n))
  }
}

def splitParam(value: String): List[String] = {
  Option(value).getOrElse("")
    .split("\\|")
    .map(_.trim)
    .filter(_.nonEmpty)
    .distinct
    .toList
}

def terms(value: String): List[String] = {
  "[A-Za-z_][A-Za-z0-9_]*".r.findAllIn(Option(value).getOrElse("")).toList.distinct
}

def jsonInt(raw: String, key: String): Int = {
  val pattern = ("\"" + key + "\":(-?\\d+)").r
  pattern.findFirstMatchIn(raw).map(_.group(1).toInt).getOrElse(-1)
}

def depJson(kind: String, symbol: String, lineStart: Int, code: String): String = {
  s"""{"kind":"${esc(kind)}","symbol":"${esc(symbol)}","line":$lineStart,"code":"${esc(code)}"}"""
}

def resultJson(
  kind: String,
  symbol: String,
  source: String,
  lineStart: Int,
  lineEnd: Int,
  method: String,
  caller: String,
  callee: String,
  code: String,
  arguments: List[String],
  controls: List[String],
  deps: List[String],
  fullName: String,
  signature: String
): String = {
  val argsJson = arguments.take(16).map(a => "\"" + esc(a) + "\"").mkString("[", ",", "]")
  val controlsJson = controls.take(8).mkString("[", ",", "]")
  val depsJson = deps.take(64).mkString("[", ",", "]")
  s"""{"kind":"${esc(kind)}","symbol":"${esc(symbol)}","source":"${esc(source)}","line":$lineStart,"line_end":$lineEnd,"method":"${esc(method)}","caller":"${esc(caller)}","callee":"${esc(callee)}","code":"${esc(code)}","arguments":$argsJson,"control_context":$controlsJson,"dependency_paths":$depsJson,"full_name":"${esc(fullName)}","signature":"${esc(signature)}"}"""
}

def esc(value: String): String = {
  Option(value).getOrElse("")
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\t", "\\t")
    .replace("\b", "\\b")
    .replace("\f", "\\f")
    .replace("\r", "")
}
