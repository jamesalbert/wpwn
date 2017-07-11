package pwn


import kotlin.system.exitProcess
import khttp.get
import khttp.responses.Response
import com.andreapivetta.kolor.*
import com.beust.klaxon.*
import mu.*
import org.json.JSONArray
import org.json.JSONObject


class Pwnr(val url: String) {
  val logger = KotlinLogging.logger {}
  val config = Parser().parse("config/defaults.json") as JsonObject
  val captured = mutableMapOf<String, MutableList<String>>("headers" to mutableListOf(), "vulnerabilities" to mutableListOf())

  init {
    println("""
             ___ ._______          ___ .______
    .___    |   |: ____  |.___    |   |:      \
    :   | /\|   ||    :  |:   | /\|   ||       |
    |   |/  :   ||   |___||   |/  :   ||   |   |
    |   /       ||___|    |   /       ||___|   |
    |______/|___|         |______/|___|    |___|
    :                     :
    :                     :

    Author: James Albert (jamesalbert)
    Message to the world: hello
    """)
    logger.info("prepare to pwn: $url")
  }

  fun request(path: String): Response = get("$url$path")

  fun isCaptured(it: JsonObject, resp: Response): Boolean {
    val desc: String = it.string("desc")!!
    if (desc in captured)
      return true
    it.array("capture")?.foreach { c: String ->
      val matches: Sequence<MatchResult> = c.toRegex().findAll(resp.text)
      if (matches.any()) {
        captured[desc] = matches.map { match: MatchResult ->
          match.groups.map { it?.value }.drop(1).joinToString(": ")
        }.distinct().toMutableList()
        return true
      }
    }
    return false
  }

  fun returnedNormally(it: JsonObject, resp: Response): Boolean {
    val expectedCode = it.int("statusCode") ?: resp.statusCode
    captured["headers"] = (captured["headers"] ?: mutableListOf()).union(resp.headers.map {
      (key, value): Map.Entry<String, String> -> key.blue() + "=" + value.red()
    }).toMutableList()
    return resp.statusCode == expectedCode
  }

  fun looksNormal(it: JsonObject, resp: Response): Boolean {
    val mustHaveText = it.boolean("mustHaveText") ?: false
    val substrings = it.array("contains") ?: JsonArray()
    if (mustHaveText and resp.text.isEmpty())
      return false
    if (substrings.isNotEmpty() and substrings.none { it in resp.text })
      return false
    if (!isCaptured(it, resp))
      return false
    if ("redirect_to" in resp.url)
      return false
    return true
  }

  fun vulnerabilities(type: String, id: String) {
    val resp = get("${this.config.string("wpvulndb")}/$type/${id.replace(".", "")}")
    val vulns = resp.jsonObject.getJSONObject(id).getJSONArray("vulnerabilities")
    for (vuln: Any in vulns) {
      if (vuln is JSONObject) {
        captured["vulnerabilities"]?.add(
            """
      |==============
      |${vuln.getString("title").blue()}
      |Find more details here:
      |${vuln.getJSONObject("references").getJSONArray("url").join("\n").red()}
      |
      """.trimMargin("|"))
      }
    }
  }

  fun check(resource: JsonObject, ext: String) {
    val name = resource.string("name")!!
    val desc = resource.string("desc")!!
    val resp = request("/$name$ext")
    val normal = this.returnedNormally(resource, resp) and
        this.looksNormal(resource, resp)
    logger.info("looking for $desc at /$name$ext")
    if (normal)
      logger.info("${"interesting url".blue()}: ${resp.url.red()}")
  }

  fun pwn() {
    if (request("/wp-login.php").statusCode != 200) {
      logger.error("$url does not appear to be up")
      exitProcess(1)
    }
    config.array("resources")?.forEach { resource: JsonObject ->
      resource.array("extensions")?.forEach { ext ->
        check(resource, ext)
      }
    }
    val version = captured["version"]?.get(0)!!
    vulnerabilities("wordpresses", version)
    captured["plugins"]?.forEach {
      vulnerabilities("plugins", it.split(":").first())
    }
  }
}

fun main(vararg args: String) {
  val url = args[0]
  val pwnr = Pwnr(url)
  pwnr.pwn()
  pwnr.captured.forEach { k: String, v: List<String> ->
    pwnr.logger.info("captured $k: \n${v.joinToString("\n")}")
  }
}
