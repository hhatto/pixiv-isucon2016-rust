<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Iscogram</title>
    <link href="/css/style.css" media="screen" rel="stylesheet" type="text/css">
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="isu-title">
          <h1><a href="/">Iscogram</a></h1>
        </div>
        <div class="isu-header-menu">
          {{ if eq .Me.ID 0}}
          <div><a href="/login">ログイン</a></div>
          {{ else }}
          <div><a href="/@{{.Me.AccountName}}"><span class="isu-account-name">{{.Me.AccountName}}</span>さん</a></div>
          {{ if eq .Me.Authority 1 }}
          <div><a href="/admin/banned">管理者用ページ</a></div>
          {{ end }}
          <div><a href="/logout">ログアウト</a></div>
          {{ end }}
        </div>
      </div>

<div class="header">
  <h1>ログイン</h1>
</div>

{{if .Flash}}
<div id="notice-message" class="alert alert-danger">
  {{.Flash}}
</div>
{{end}}

<div class="submit">
  <form method="post" action="/login">
    <div class="form-account-name">
      <span>アカウント名</span>
      <input type="text" name="account_name">
    </div>
    <div class="form-password">
      <span>パスワード</span>
      <input type="password" name="password">
    </div>
    <div class="form-submit">
      <input type="submit" name="submit" value="submit">
    </div>
  </form>
</div>

<div class="isu-register">
  <a href="/register">ユーザー登録</a>
</div>

    </div>
    <script src="/js/jquery-2.2.0.js"></script>
    <script src="/js/jquery.timeago.js"></script>
    <script src="/js/jquery.timeago.ja.js"></script>
    <script src="/js/main.js"></script>
  </body>
</html>
