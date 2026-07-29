import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import java.nio.file.{Files, Paths}

@main def main(cpgPath: String, sourcePath: String, functionName: String, functionSignature: String, startLine: String, outputPath: String): Unit = {
  importCpg(cpgPath)

  val targetStartLine = scala.util.Try(startLine.toInt).getOrElse(1)
  val sourceSuffix = sourcePath.replace("\\", "/")
  val methodName = functionName
  val methodLeaf = canonMethodIdentity(functionName).split("::").lastOption.getOrElse(functionName)
  val contextMethodLimit = envInt("APR_JOERN_CONTEXT_METHOD_LIMIT", 48)
  val totalMethodLimit = envInt("APR_JOERN_TOTAL_METHOD_LIMIT", 96)

  val selected = selectTargetMethods(sourceSuffix, methodName, functionSignature, targetStartLine)
  val methods = selected._1
  val uncertainties = selected._2

  val method = methods.headOption
  val directCallees = method.toList.flatMap { m =>
    m.call.nameNot("<operator>.*").nameNot("<unknown>").name.l.distinct
      .flatMap { calleeName =>
        cpg.method.nameExact(calleeName)
          .l
      }
  }.distinct
  val callerMethods =
    if (method.nonEmpty && methodLeaf.nonEmpty) cpg.call.nameExact(methodLeaf).method.l.distinct
    else List[io.shiftleft.codepropertygraph.generated.nodes.Method]()
  val methodsToAnalyze =
    (method.toList ++ directCallees.take(contextMethodLimit) ++ callerMethods.take(contextMethodLimit))
      .distinct
      .take(totalMethodLimit)
  val ops = methodsToAnalyze.flatMap { m =>
    val methodRole =
      if (method.exists(_.id == m.id)) "target_method"
      else if (directCallees.exists(_.id == m.id)) "direct_callee_method"
      else if (callerMethods.exists(_.id == m.id)) "caller_method"
      else "related_method"
    val controls = m.controlStructure.l.map { c =>
      s"""{"kind":"${esc(c.controlStructureType)}","line":${line(c)},"line_end":${lineEnd(c)},"code":"${esc(c.code)}"}"""
    }
    val methodDef = opJson(
      "method_definition",
      m.name,
      m.filename,
      line(m),
      lineEnd(m),
      m.code,
      List(methodRole),
      "",
      m.fullName,
      List(),
      List(),
      methodDependencies(m, methodRole)
    )
    val returns = m.ast.isReturn.l.map { n =>
      val nodeControls = controlsFor(n, controls)
      opJson(
        "return_statement",
        m.name,
        m.filename,
        line(n),
        lineEnd(n),
        n.code,
        List(methodRole),
        "",
        "",
        List(),
        nodeControls,
        dependencyPaths(n, m, methodRole, "return_statement", nodeControls)
      )
    }
    val calls = m.call.l.map { n =>
      val args = n.argument.l.sortBy(a => a.argumentIndex).map(_.code)
      val nodeControls = controlsFor(n, controls)
      opJson(
        "call_expression",
        m.name,
        m.filename,
        line(n),
        lineEnd(n),
        n.code,
        List(methodRole),
        n.name,
        n.methodFullName,
        args,
        nodeControls,
        dependencyPaths(n, m, methodRole, "call_expression", nodeControls)
      )
    }
    val assignments = m.call.name("<operator>.assignment").l.map { n =>
      val args = n.argument.l.sortBy(a => a.argumentIndex).map(_.code)
      val nodeControls = controlsFor(n, controls)
      opJson(
        "assignment_expression",
        m.name,
        m.filename,
        line(n),
        lineEnd(n),
        n.code,
        List(methodRole),
        n.name,
        n.methodFullName,
        args,
        nodeControls,
        dependencyPaths(n, m, methodRole, "assignment_expression", nodeControls)
      )
    }
    val branches = m.controlStructure.l.map { n =>
      val nodeControls = controlsFor(n, controls)
      opJson(
        "control_structure",
        m.name,
        m.filename,
        line(n),
        lineEnd(n),
        n.code,
        List(methodRole),
        "",
        "",
        List(),
        nodeControls,
        dependencyPaths(n, m, methodRole, "control_structure", nodeControls)
      )
    }
    (List(methodDef) ++ returns ++ calls ++ assignments ++ branches)
      .filter(_.contains("\"line\":"))
      .distinct
      .take(160)
  }
  val typeNames = method.toList.flatMap { m =>
    (m.parameter.typeFullName.l ++ m.local.typeFullName.l)
      .map(_.split("\\.").lastOption.getOrElse(""))
      .map(_.replace("*", "").replace("const ", "").trim)
      .filter(_.nonEmpty)
  }.distinct.take(40)
  val typeOps = typeNames.flatMap { typeName =>
    cpg.typeDecl.nameExact(typeName).l.take(4).map { t =>
      opJson("type_definition", t.name, t.filename, line(t), lineEnd(t), t.code, List(), "", t.fullName, List(), List(), List())
    }
  }

  val json = s"""{"provider":"joern","operations":[${(ops ++ typeOps).mkString(",")}],"uncertainties":[${uncertainties.map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
  Files.write(Paths.get(outputPath), json.getBytes("UTF-8"))
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

def envInt(name: String, defaultValue: Int): Int = {
  scala.util.Try(sys.env.getOrElse(name, defaultValue.toString).toInt)
    .getOrElse(defaultValue)
}

def controlsFor(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode, controls: List[String]): List[String] = {
  val ln = line(n)
  controls.filter { raw =>
    val linePattern = """"line":(-?\d+)""".r
    val endPattern = """"line_end":(-?\d+)""".r
    val start = linePattern.findFirstMatchIn(raw).map(_.group(1).toInt).getOrElse(-1)
    val end = endPattern.findFirstMatchIn(raw).map(_.group(1).toInt).getOrElse(start)
    start > 0 && ln >= start && (end <= start || ln <= end)
  }.takeRight(6)
}

def methodDependencies(m: io.shiftleft.codepropertygraph.generated.nodes.Method, methodRole: String): List[String] = {
  val params = m.parameter.l
    .filter(p => Option(p.name).getOrElse("").nonEmpty)
    .take(24)
    .map { p =>
      depJson(
        "parameter_flow",
        "method_parameter",
        m.name,
        line(p),
        p.name,
        p.code,
        methodRole,
        "method parameter can seed data flow inside this method"
      )
    }
  val locals = m.local.l
    .filter(l => Option(l.name).getOrElse("").nonEmpty)
    .filter(l => !noiseIdentifier(l.name))
    .filter(l => !Option(l.code).getOrElse("").startsWith("<unknown>"))
    .take(24)
    .map { l =>
      depJson(
        "local_symbol",
        "method_local",
        m.name,
        -1,
        l.name,
        l.code,
        methodRole,
        "method local variable participates in target slice"
      )
    }
  (params ++ locals).take(48)
}

def dependencyPaths(
  n: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
  m: io.shiftleft.codepropertygraph.generated.nodes.Method,
  methodRole: String,
  opKind: String,
  controlJsons: List[String]
): List[String] = {
  val semanticFlows = semanticDataflowDeps(n, m, methodRole)
  val controlDeps = controlJsons.takeRight(8).map { raw =>
    val cLine = jsonInt(raw, "line")
    val cKind = jsonString(raw, "kind")
    val cCode = jsonString(raw, "code")
    depJson(
      "control_dependency",
      cKind,
      m.name,
      cLine,
      controlCondition(cCode),
      cCode,
      methodRole,
      "operation is control-dependent on this branch/loop/switch"
    )
  }
  val nodeSymbols = identifiersFor(n).filterNot(noiseIdentifier).distinct.take(40)
  val paramDeps = m.parameter.l
    .filter(p => nodeSymbols.contains(p.name))
    .take(16)
    .map { p =>
      depJson(
        "parameter_data_dependency",
        "parameter",
        m.name,
        line(p),
        p.name,
        p.code,
        methodRole,
        "operation uses a method parameter"
      )
    }
  val localDeps = m.local.l
    .filter(l => nodeSymbols.contains(l.name))
    .take(16)
    .map { l =>
      depJson(
        "local_data_dependency",
        "local",
        m.name,
        -1,
        l.name,
        l.code,
        methodRole,
        "operation uses a method local"
      )
    }
  val reachingDefs = reachingDefinitionDeps(n, m, nodeSymbols, methodRole)
  val callArgDeps = n match {
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
      c.argument.l.sortBy(a => a.argumentIndex).take(16).map { arg =>
        depJson(
          "argument_flow",
          "call_argument",
          m.name,
          line(arg),
          Option(c.name).getOrElse(""),
          arg.code,
          methodRole,
          s"argument ${arg.argumentIndex} flows into call ${Option(c.name).getOrElse("")}"
        )
      }
    case _ => List[String]()
  }
  val returnDeps =
    if (opKind == "return_statement") {
      nodeSymbols.take(16).map { sym =>
        depJson(
          "return_data_dependency",
          "return_symbol",
          m.name,
          line(n),
          sym,
          n.code,
          methodRole,
          "symbol contributes to method return value"
        )
      }
    } else {
      List[String]()
    }
  (semanticFlows ++ controlDeps ++ paramDeps ++ localDeps ++ reachingDefs ++ callArgDeps ++ returnDeps)
    .distinct
    .take(80)
}

def semanticDataflowDeps(
  n: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
  m: io.shiftleft.codepropertygraph.generated.nodes.Method,
  methodRole: String
): List[String] = {
  n match {
    case sink: io.shiftleft.codepropertygraph.generated.nodes.CfgNode =>
      scala.util.Try {
        sink.start.reachableByFlows(m.parameter).l.take(12).map { flow =>
          val elements = flow.elements.take(24)
          val pathNodes = elements.map { node =>
            s"""{"line":${line(node)},"code":"${esc(Option(node.code).getOrElse(""))}"}"""
          }.mkString("[", ",", "]")
          val first = elements.headOption
          val symbol = first.map(node => identifiersFor(node).headOption.getOrElse(Option(node.code).getOrElse(""))).getOrElse("")
          val firstLine = first.map(line).getOrElse(-1)
          val pathCode = elements.map(node => Option(node.code).getOrElse("")).filter(_.nonEmpty).mkString(" -> ")
          s"""{"kind":"semantic_dataflow_path","relation":"reachable_by_flow","method":"${esc(Option(m.name).getOrElse(""))}","line":$firstLine,"symbol":"${esc(symbol)}","code":"${esc(pathCode)}","role":"${esc(methodRole)}","reason":"Joern reachableByFlows path from method parameter to operation","path_nodes":$pathNodes}"""
        }
      }.getOrElse(List[String]())
    case _ => List[String]()
  }
}

def reachingDefinitionDeps(
  n: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
  m: io.shiftleft.codepropertygraph.generated.nodes.Method,
  nodeSymbols: List[String],
  methodRole: String
): List[String] = {
  val ln = line(n)
  if (ln <= 0 || nodeSymbols.isEmpty) {
    return List[String]()
  }
  val deps = m.call.name("<operator>.assignment").l
    .filter(a => line(a) > 0 && line(a) != ln)
    .flatMap { a =>
      val args = a.argument.l.sortBy(_.argumentIndex)
      val lhsSymbols = args.headOption.map(identifiersFor).getOrElse(List()).filterNot(noiseIdentifier)
      val hits = lhsSymbols.filter(nodeSymbols.contains).distinct
      hits.map { sym =>
        val isForward = line(a) > ln
        val kind = if (isForward) "forward_assignment" else "reaching_definition"
        val detail =
          if (isForward) "later assignment updates a symbol used by this operation"
          else "nearest earlier assignment defines a symbol used by this operation"
        (
          line(a),
          isForward,
          depJson(
            kind,
            "assignment",
            m.name,
            line(a),
            sym,
            a.code,
            methodRole,
            detail
          )
        )
      }
    }
  val backward = deps.filter { case (_, isForward, _) => !isForward }.sortBy(_._1).takeRight(24).map(_._3)
  val forward = deps.filter { case (_, isForward, _) => isForward }.sortBy(_._1).take(24).map(_._3)
  backward ++ forward
}

def selectTargetMethods(sourcePath: String, functionName: String, functionSignature: String, startLine: Int): (List[io.shiftleft.codepropertygraph.generated.nodes.Method], List[String]) = {
  val sourceNorm = normalizePath(sourcePath)
  val sourceBase = baseName(sourceNorm)
  val requested = canonMethodIdentity(functionName)
  val leaf = requested.split("::").lastOption.getOrElse(requested)
  val byLeaf =
    if (leaf.nonEmpty) cpg.method.nameExact(leaf).l
    else cpg.method.l
  val scoped = byLeaf.filter(m => !requested.contains("::") || canonMethodIdentity(Option(m.fullName).getOrElse("")).contains(requested))
  val byIdentity = if (scoped.nonEmpty) scoped else byLeaf
  val signatureNorm = canonMethodIdentity(functionSignature)
  val signatureMatched = byIdentity.filter(m => signatureNorm.nonEmpty && (canonMethodIdentity(Option(m.signature).getOrElse("")) == signatureNorm || canonMethodIdentity(Option(m.code).getOrElse("")).contains(signatureNorm)))
  val bySignature = if (signatureMatched.nonEmpty) signatureMatched else byIdentity
  val lineMatched = bySignature.filter(m => startLine > 0 && m.lineNumber.exists(_ == startLine))
  val byName = if (lineMatched.nonEmpty) lineMatched else bySignature
  if (sourceNorm.isEmpty) {
    return (byName, List[String]())
  }
  val strict = byName.filter(m => strictSourceMatch(Option(m.filename).getOrElse(""), sourceNorm))
  if (strict.nonEmpty) {
    return (strict, List[String]())
  }
  val basenameFiles = cpg.method.l
    .map(m => normalizePath(Option(m.filename).getOrElse("")))
    .filter(f => baseName(f) == sourceBase)
    .distinct
  val basenameMatches = byName.filter(m => baseName(Option(m.filename).getOrElse("")) == sourceBase)
  if (basenameMatches.nonEmpty && basenameFiles.size == 1) {
    return (basenameMatches, List("joern_source_match_used_unique_basename_fallback"))
  }
  if (basenameMatches.nonEmpty && basenameFiles.size > 1) {
    return (List[io.shiftleft.codepropertygraph.generated.nodes.Method](), List("joern_source_match_ambiguous_basename:" + sourceBase))
  }
  (List[io.shiftleft.codepropertygraph.generated.nodes.Method](), List("joern_source_match_failed:" + sourceNorm))
}

def canonMethodIdentity(value: String): String = {
  Option(value).getOrElse("").replaceAll("\\s+", "").replaceAll("\\.", "::").replaceAll("<[^<>]*>", "")
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

def identifiersFor(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): List[String] = {
  n.ast.isIdentifier.name.l.distinct
}

def identifiersInText(code: String): List[String] = {
  "[A-Za-z_][A-Za-z0-9_]*".r.findAllIn(Option(code).getOrElse("")).toList.distinct
}

def noiseIdentifier(value: String): Boolean = {
  Set(
    "if", "else", "switch", "case", "return", "sizeof", "const", "struct",
    "static", "break", "continue", "NULL", "true", "false", "int", "char",
    "void", "size_t"
  ).contains(Option(value).getOrElse(""))
}

def controlCondition(code: String): String = {
  val text = Option(code).getOrElse("").trim
  val start = text.indexOf("(")
  val end = text.lastIndexOf(")")
  if (start >= 0 && end > start) text.substring(start + 1, end).trim else text.take(240)
}

def jsonString(raw: String, key: String): String = {
  val pattern = ("\"" + key + "\":\"((?:\\\\.|[^\"])*)\"").r
  pattern.findFirstMatchIn(raw).map(m => unesc(m.group(1))).getOrElse("")
}

def jsonInt(raw: String, key: String): Int = {
  val pattern = ("\"" + key + "\":(-?\\d+)").r
  pattern.findFirstMatchIn(raw).map(_.group(1).toInt).getOrElse(-1)
}

def unesc(value: String): String = {
  Option(value).getOrElse("")
    .replace("\\n", "\n")
    .replace("\\\"", "\"")
    .replace("\\\\", "\\")
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

def symbolsJson(code: String, callName: String, args: List[String]): String = {
  val text = Option(code).getOrElse("")
  val ids = "[A-Za-z_][A-Za-z0-9_]*".r.findAllIn(text).toList.distinct.filterNot { token =>
    Set("if", "else", "switch", "case", "return", "sizeof", "const", "struct", "static", "break", "NULL").contains(token)
  }
  val macros = ids.filter(t => t.exists(_.isUpper) && t.toUpperCase == t)
  val calls = if (callName.nonEmpty && !callName.startsWith("<operator>")) List(callName) else List()
  val argIds = args.flatMap(arg => "[A-Za-z_][A-Za-z0-9_]*".r.findAllIn(arg).toList).distinct
  s""""symbols":{"calls":[${calls.map(x => "\"" + esc(x) + "\"").mkString(",")}],"identifiers":[${ids.take(40).map(x => "\"" + esc(x) + "\"").mkString(",")}],"macro_like":[${macros.take(30).map(x => "\"" + esc(x) + "\"").mkString(",")}],"argument_identifiers":[${argIds.take(40).map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
}

def depJson(kind: String, relation: String, methodName: String, lineStart: Int, symbol: String, code: String, role: String, reason: String): String = {
  s"""{"kind":"${esc(kind)}","relation":"${esc(relation)}","method":"${esc(methodName)}","line":$lineStart,"symbol":"${esc(symbol)}","code":"${esc(code)}","role":"${esc(role)}","reason":"${esc(reason)}"}"""
}

def opJson(kind: String, methodName: String, fileName: String, lineStart: Int, lineEnd: Int, code: String, roles: List[String], callName: String, methodFullName: String, args: List[String], controls: List[String], deps: List[String]): String = {
  val roleJson = roles.map(r => "\"" + esc(r) + "\"").mkString("[", ",", "]")
  val controlsJson = controls.take(6).mkString("[", ",", "]")
  val depsJson = deps.take(80).mkString("[", ",", "]")
  val argsJson = args.take(16).map(a => "\"" + esc(a) + "\"").mkString("[", ",", "]")
  val symbolJson = symbolsJson(code, callName, args)
  s"""{"kind":"${esc(kind)}","method":"${esc(methodName)}","source":"${esc(fileName)}","line":$lineStart,"line_end":$lineEnd,"code":"${esc(code)}","call_name":"${esc(callName)}","method_full_name":"${esc(methodFullName)}","arguments":$argsJson,"roles":$roleJson,"control_ancestors":$controlsJson,"dependency_paths":$depsJson,$symbolJson}"""
}
