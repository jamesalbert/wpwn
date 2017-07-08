package pwn


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

  fun vulnerabilities() {
    val version: String?
    /*val resp: Response*/
    val vulns: JSONArray
    version = this.captured.get("version")?.get(0)!!
    /*resp = get(this.config.string("wpvulndb") + version.replace(".", ""))
    vulns = resp.jsonObject.getJSONObject(version).getJSONArray("vulnerabilities")*/
    vulns = JSONObject("""
      {
        "4.7.5": {
          "vulnerabilities": [
            {
              "updated_at": "2017-05-23T08:26:43.000Z",
              "references": {"cve":["2017-8295"],
                "url": [
                  "https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html",
                  "http://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html"
                ]
              },
              "vuln_type": "UNKNOWN",
              "created_at": "2017-05-05T09:47:44.000Z",
              "fixed_in": null,
              "id": 8807,
              "title": "WordPress 2.3-4.7.5 - Host Header Injection in Password Reset",
              "published_date":"2017-05-03T00:00:00.000Z"
            }
          ]
        }
      }
    """.trim()).getJSONObject(version).getJSONArray("vulnerabilities")
    for (vuln: Any in vulns) {
      if (vuln is JSONObject) {
        this.captured["vulnerabilities"]?.add(
          """
          |==============
          |CVE: ${Kolor.foreground(
            vuln.getJSONObject("references").getJSONArray("cve").get(0) as String,
            Color.GREEN
           )}
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
    }
    this.vulnerabilities()
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
