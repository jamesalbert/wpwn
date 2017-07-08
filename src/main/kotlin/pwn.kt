package pwn


import khttp.get
import khttp.responses.Response
import com.beust.klaxon.*
import mu.*


class Pwnr(url: String) {
  val url: String
  val logger: KLogger
  val config: JsonObject
  val captured: MutableMap<String, List<String?>?>

  init {
    this.url = url
    this.config = Parser().parse("config/defaults.json") as JsonObject
    this.captured = mutableMapOf()
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
        match.groups.get(1)?.value
      }?.toList()?.distinct()
      return true
    }
  }

  fun returnedNormally(it: JsonObject, resp: Response): Boolean {
    val expectedCode: Int
    expectedCode = it.int("statusCode") ?: resp.statusCode
    this.captured["headers"] = resp.headers.map { t: Map.Entry<String, String> ->
      "\n${t.key}=${t.value}"
    }.toList()
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

  fun pwn() {
    val resources: JsonArray<JsonObject>?
    var extensions: JsonArray<String>?
    var name: String
    var desc: String
    var path: String
    var normal: Boolean
    var resp: Response
    resources = this.config.array("resources")
    resources?.forEach { resource: JsonObject ->
      name = resource.string("name")!!
      desc = resource.string("desc")!!
      path = "/$name"
      extensions = resource.array("extensions")
      extensions?.forEach { ext ->
        this.logger.info("looking for ${desc} at ${path+ext}")
        resp = this.request(path + ext)
        normal = this.returnedNormally(resource, resp) and
                 this.looksNormal(resource, resp)
        when (normal) { true ->
          this.logger.info("interesting url: ${resp.url}")
        }
      }
    }
  }
}

fun main(vararg args: String) {
  val url: String = args[0]
  var pwnr = Pwnr(url)
  pwnr.pwn()
  pwnr.captured.forEach { k: String, v: List<String?>? ->
    pwnr.logger.info("captured $k: ${v?.joinToString(", ")}")
  }
}
