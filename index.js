'use strict';

const LANG_T = antSword['language']['toastr'];
const LANG = require('./language');
const WIN = require('ui/window');
/**
 * Plugin
 */
class Plugin {
  getdistinctres(a, b) {
    let arr = a.concat(b)
    let result = []
    let obj = {}
    for (let i of arr) {
      let k = `${i.name}:${i.line}`;
      if (!obj[k]) {
        result.push(i)
        obj[k] = 1
      }
    }
    return result
  }
  constructor(opt) {
    let self = this;

    // Create window
    let win = new WIN({
      title: `${LANG['title']}`,
      height: 428,
      width: 688,
    });

    // 初始化 toolbar
    let toolbar = win.win.attachToolbar();
    toolbar.loadStruct([{
      id: 'start',
      type: 'button',
      text: LANG['toolbar']['start'],
      icon: 'play',
    }]);

    let grid = win.win.attachGrid();
    grid.setHeader(`
      ${LANG['grid']['name']},
      ${LANG['grid']['line']},
      ${LANG['grid']['code']}
    `);
    grid.setColTypes("txt,ro,txt");
    grid.setColSorting('str,int,str');
    grid.setInitWidths("200,50,*");
    grid.setColAlign("left,left,left");
    grid.enableMultiselect(true);
    grid.setEditable(true);
    grid.init();
    self.grid = grid;
    // 点击事件
    toolbar.attachEvent('onClick', (id) => {
      switch (id) {
        case 'start':
          self.grid.clearAll();
          win.win.progressOn();
          // 实例化 Shell Core
          let core = new antSword['core'][opt['type']](opt);
          // 向Shell发起请求
          core.request({
            _: self.getPayload(opt['type'])
          }).then((_ret) => { // 处理返回数据
            let griddata = [];
            var _r = JSON.parse(_ret['text']);
            _r = self.getdistinctres([], _r);
            _r.map((a, i) => {
              griddata.push({
                id: i,
                data: [antSword.noxss(a.name), parseInt(a.line), antSword.noxss(a.code)],
              });
            });
            self.grid.parse({
              rows: griddata
            }, "json");
            toastr.success(LANG['success'], LANG_T['success']);
            win.win.progressOff();
          }).catch((err) => { // 处理异常数据
            toastr.error(`${LANG['error']}: ${JSON.stringify(err)}`, LANG_T['error']);
            win.win.progressOff();
          });
          break;
        default:
          break;
      }
    });
  }

  getPayload(shelltype) {
    let codes = {
      php: `set_time_limit(0);$a=$_SERVER["DOCUMENT_ROOT"];$a=$a==''?'.':$a;$b=array_merge(glob("$a/*.php"),glob("$a/*.inc"));$c=['(\\$_(GET|POST|REQUEST)\\[.{0,15}\\]\\s{0,10}\\(\\s{0,10}\\$_(GET|POST|REQUEST)\\[.{0,15}\\]\\))','((eval|assert)(\\s|\\n)*\\((\\s|\\n)*\\$_(POST|GET|REQUEST)\\[.{0,15}\\]\\))','(eval(\\s|\\n)*\\(base64_decode(\\s|\\n)*\\((.|\\n){1,200})','(function\\_exists\\s*\\(\\s*[\\'|\\"](popen|exec|proc\\_open|passthru)+[\\'|\\"]\\s*\\))','((exec|shell\\_exec|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*\\))','(\\$(\\w+)\\s*\\(\\s.chr\\(\\d+\\)\\))','(\\$(\\w+)\\s*\\$\\{(.*)\\})','(\\$(\\w+)\\s*\\(\\s*\\$\\_(GET|POST|REQUEST|COOKIE|SERVER)+\\[(.*)\\]\\s*\\))','(\\$\\_(GET|POST|REQUEST|COOKIE|SERVER)+\\[(.*)\\]\\(\\s*\\$(.*)\\))','(\\$\\_\\=(.*)\\$\\_)','(\\$(.*)\\s*\\((.*)\\/e(.*)\\,\\s*\\$\\_(.*)\\,(.*)\\))','(new com\\s*\\(\\s*[\\'|\\"]shell(.*)[\\'|\\"]\\s*\\))','(echo\\s*curl\\_exec\\s*\\(\\s*\\$(\\w+)\\s*\\))','((fopen|fwrite|fputs|file\\_put\\_contents)+\\s*\\((.*)\\$\\_(GET|POST|REQUEST|COOKIE|SERVER)+\\[(.*)\\](.*)\\))','(\\(\\s*\\$\\_FILES\\[(.*)\\]\\[(.*)\\]\\s*\\,\\s*\\$\\_(GET|POST|REQUEST|FILES)+\\[(.*)\\]\\[(.*)\\]\\s*\\))','(\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once)+\\s*\\(\\s*\\$(\\w+)\\s*\\))','((include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\"](\\w+)\\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\\'|\\"]\\s*\\))','(eval\\s*\\(\\s*\\(\\s*\\$\\$(\\w+))','((eval|assert|include|require|include\\_once|require\\_once|array\\_map|array\\_walk)+\\s*\\(\\s*\\$\\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\\[(.*)\\]\\s*\\))','(preg\\_replace\\s*\\((.*)\\(base64\\_decode\\(\\$)'];$e=[];foreach($b as $f){$g=file_get_contents($f);$h=explode("\\n",$g);foreach($c as $i){if(preg_match_all("/$i/iU",$g,$j)){foreach($h as $k=>$n){if(preg_match_all("/$i/iU",$n,$j)){array_push($e, array("name"=>"{$f}","line"=>$k,"code"=> "{$j[0][0]}"));}}}}}echo json_encode($e);`,
      // asp: 'Dim S:SET C=CreateObject("Scripting.FileSystemObject"):If Err Then:S="ERROR:// "&Err.Description:Err.Clear:Else:S=Server.Mappath(".")&chr(9):For Each D in C.Drives:S=S&D.DriveLetter&chr(58):Next:End If:Response.Write(S)',
      // aspx: 'var c=System.IO.Directory.GetLogicalDrives();Response.Write(Server.MapPath(".")+"\t");for(var i=0;i<=c.length-1;i++)Response.Write(c[i][0]+":");Response.Write("\t"+Environment.OSVersion+"\t");Response.Write(Environment.UserName);',
      // custom: 'A',
    }
    return codes[shelltype];
  }
}

module.exports = Plugin;