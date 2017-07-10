package pwn


import kotlin.system.exitProcess
import khttp.get
import khttp.responses.Response
import com.andreapivetta.kolor.*
import com.beust.klaxon.*
import mu.*
import org.json.JSONArray
import org.json.JSONObject


class Pwnr(url: String) {
  val url: String
  val logger: KLogger
  val config: JsonObject
  val captured: MutableMap<String, MutableList<String?>?>

  init {
    this.url = url
    this.config = Parser().parse("config/defaults.json") as JsonObject
    this.captured = mutableMapOf()
    this.captured["headers"] = mutableListOf<String?>()
    this.captured["vulnerabilities"] = mutableListOf<String?>()
    this.logger = KotlinLogging.logger {}
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
    this.logger.info("prepare to pwn: $url")
  }

  fun request(path: String): Response {
    return get("${this.url}$path")
  }

  fun isCaptured(it: JsonObject, resp: Response): Boolean {
    val capture: JsonArray<String>?
    val desc: String
    capture = it.array("capture") ?: JsonArray()
    desc = it.string("desc")!!
    return capture.isNotEmpty() and capture.any { c: String ->
      val regex: Regex = c.toRegex()
      val matches: Sequence<MatchResult>? = regex.findAll(resp.text)
      if (matches?.count() == 0)
        return false
      if (this.captured.containsKey(desc))
        return true
      this.captured[desc] = matches?.map { match: MatchResult ->
        match.groups.map { g: MatchGroup? ->
          g?.value
        }.drop(1).joinToString(": ") as String?
      }?.distinct()?.toMutableList()
      return true
    }
  }

  fun returnedNormally(it: JsonObject, resp: Response): Boolean {
    val expectedCode: Int
    val headers: List<String?>?
    expectedCode = it.int("statusCode") ?: resp.statusCode
    headers = this.captured["headers"]?.union(resp.headers.map {
      t: Map.Entry<String, String> ->
        """
        |${
          Kolor.foreground(
            "${t.key}",
            Color.BLUE
          )
        }=${
          Kolor.foreground(
            "${t.value}",
            Color.RED
          )
        }
        """.trimMargin("|")
    }.distinct())?.toMutableList()
    this.captured["headers"] = headers
    return resp.statusCode.equals(expectedCode)
  }

  fun looksNormal(it: JsonObject, resp: Response): Boolean {
    val mustHaveText: Boolean
    val substrings: JsonArray<String>?
    mustHaveText = it.boolean("mustHaveText") ?: false
    substrings = it.array("contains") ?: JsonArray()
    if (mustHaveText and resp.text.isEmpty())
      return false
    if (substrings.isNotEmpty() and !substrings.any { s ->
      resp.text.contains(s)
    })
      return false
    if (!this.isCaptured(it, resp))
      return false
    if (resp.url.contains("redirect_to"))
      return false
    return true
  }

  fun vulnerabilities(type: String, id: String) {
    val resp: Response
    val vulns: JSONArray
    resp = get("${this.config.string("wpvulndb")}/$type/${id.replace(".", "")}")
    vulns = resp.jsonObject.getJSONObject(id).getJSONArray("vulnerabilities")
    for (vuln: Any in vulns) {
      if (vuln is JSONObject) {
        this.captured["vulnerabilities"]?.add(
          """
          |==============
          |${Kolor.foreground(vuln.getString("title"), Color.BLUE)}
          |Find more details here:
          |${Kolor.foreground(
              vuln.getJSONObject("references").getJSONArray("url").join("\n"),
              Color.RED
           )}
          |
          """.trimMargin("|"))
      }
    }
  }

  fun check(resource: JsonObject, ext: String) {
    var name: String
    var desc: String
    val resp: Response
    val normal: Boolean
    name = resource.string("name")!!
    desc = resource.string("desc")!!
    resp = this.request("/$name$ext")
    normal = this.returnedNormally(resource, resp) and
             this.looksNormal(resource, resp)
    this.logger.info("looking for $desc at /$name$ext")
    when (normal) { true ->
      this.logger.info(
        """
        |${
          Kolor.foreground("interesting url", Color.BLUE)
        }: ${
          Kolor.foreground(resp.url, Color.RED)
        }
        """.trimMargin("|")
      )
    }
  }

  fun pwn() {
    val resources: JsonArray<JsonObject>?
    val version: String
    var extensions: JsonArray<String>?
    if (this.request("/wp-login.php").statusCode != 200) {
      this.logger.error("${this.url} does not appear to be up")
      exitProcess(1)
    }
    resources = this.config.array("resources")
    resources?.forEach { resource: JsonObject ->
      extensions = resource.array("extensions")
      extensions?.forEach { ext ->
        check(resource, ext)
      }
    }
    version = this.captured.get("version")?.get(0)!!
    this.vulnerabilities("wordpresses", version)
    this.captured.get("plugins")?.forEach {
      val plugin: String
      plugin = it?.split(":")?.first()!!
      this.vulnerabilities("plugins", plugin)
    }
  }
}

fun main(vararg args: String) {
  val url: String = args[0]
  var pwnr = Pwnr(url)
  pwnr.pwn()
  pwnr.captured.forEach { k: String, v: List<String?>? ->
    pwnr.logger.info("captured $k: ${"\n" + v?.joinToString("\n")}")
  }
}
