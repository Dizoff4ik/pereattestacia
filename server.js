require("dotenv").config();
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
const isProd = process.env.NODE_ENV === "production";
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing. Copy .env.example to .env and configure PostgreSQL.");
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters.");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: isProd, maxAge: 1000 * 60 * 60 * 12 }
}));
app.use(express.static(path.join(__dirname, "public")));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });

const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const safeUser = u => ({ id: u.id, username: u.username, email: u.email, role: u.role, active: u.active });
function requireAuth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"Нужно войти в аккаунт."}); next(); }
function requireActive(req,res,next){ if(!req.session.user?.active) return res.status(403).json({error:"Аккаунт отключён. Обратитесь к администратору."}); next(); }
function requireRole(...roles){return (req,res,next)=>{if(!req.session.user) return res.status(401).json({error:"Нужно войти в аккаунт."});if(!roles.includes(req.session.user.role))return res.status(403).json({error:"Недостаточно прав."});next();};}
function requireStaff(req,res,next){if(!req.session.user)return res.status(401).json({error:"Нужно войти в аккаунт."});if(!["admin","curator"].includes(req.session.user.role))return res.status(403).json({error:"Недостаточно прав."});next();}
function validEmail(s){return typeof s==="string" && s.length<=254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);}
function validPassword(s){return typeof s==="string" && s.length>=10 && s.length<=200;}
async function init(){
  const schema=fs.readFileSync(path.join(__dirname,"schema.sql"),"utf8");
  await pool.query(schema);
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id VARCHAR(40) UNIQUE");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique ON users (lower(username))");
  
  const promoteEmail = process.env.PROMOTE_ADMIN_EMAIL?.trim().toLowerCase();

  if (promoteEmail && validEmail(promoteEmail)) {
  const result = await pool.query(
      "UPDATE users SET role='admin' WHERE lower(email)=lower($1) RETURNING id, username, email, role",
      [promoteEmail]
    );

    if (result.rowCount === 1) {
      console.log("Admin role assigned to configured account.");
    } else {
      console.log("Admin promotion skipped: account not found.");
    }
  }

  const adminCount=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'");
  if(Number(adminCount.rows[0].n)===0 && process.env.BOOTSTRAP_ADMIN_EMAIL && process.env.BOOTSTRAP_ADMIN_PASSWORD){
    if(!validEmail(process.env.BOOTSTRAP_ADMIN_EMAIL)||!validPassword(process.env.BOOTSTRAP_ADMIN_PASSWORD)){
      console.warn("Bootstrap admin not created: check BOOTSTRAP_ADMIN_EMAIL and use a password of at least 10 characters.");
    } else {
      const hash=await bcrypt.hash(process.env.BOOTSTRAP_ADMIN_PASSWORD,12);
      await pool.query("INSERT INTO users(username,email,password_hash,role) VALUES($1,lower($2),$3,'admin') ON CONFLICT(email) DO NOTHING",
        [process.env.BOOTSTRAP_ADMIN_USERNAME||"Главный администратор",process.env.BOOTSTRAP_ADMIN_EMAIL,hash]);
      console.log("Bootstrap administrator account checked.");
    }
  }
  const count=await pool.query("SELECT COUNT(*)::int AS n FROM tests");
  if(Number(count.rows[0].n)===0){
    const seed=await pool.query("INSERT INTO tests(title,description,active) VALUES ('Переаттестация 1','Базовые правила и обязанности саппорта',true),('Переаттестация 2','Коммуникация и субординация',true),('Переаттестация 3','Терминология и внимательность',true) RETURNING id,title");
    const sample=[
      ["Что следует сделать, если вы не уверены в правильности ответа пользователю?",["Ответить наугад","Уточнить информацию у вышестоящего","Проигнорировать вопрос","Придумать правило"],1],
      ["Можно ли вмешиваться в работу другой подветки без согласования?",["Да, всегда","Нет, нужно соблюдать правила взаимодействия","Можно тайно","Можно, если хочется"],1],
      ["Где проверять актуальные требования к работе?",["В актуальных официальных инструкциях","В случайных сообщениях","Только по памяти","В догадках"],0],
      ["Как следует общаться с пользователем?",["Грубо и резко","Спокойно и уважительно","Игнорировать","Использовать оскорбления"],1],
      ["Что делать при обнаружении ошибки в инструкции?",["Молча менять её","Сообщить ответственному лицу","Распространить слух","Ничего не делать"],1],
      ["Можно ли передавать пароль другому человеку?",["Да","Нет, пароль конфиденциален","Только знакомому","В общем чате"],1],
      ["Как поступить, если задача выходит за пределы полномочий?",["Самовольно принять решение","Передать вопрос уполномоченному сотруднику","Удалить обращение","Игнорировать"],1],
      ["Что важно сделать перед завершением обращения?",["Убедиться, что вопрос обработан и зафиксирован","Закрыть без проверки","Удалить историю","Ничего"],0],
      ["Как нужно обращаться с внутренней информацией?",["Публиковать где угодно","Соблюдать правила доступа и конфиденциальности","Отправлять всем подряд","Использовать в личных целях"],1],
      ["Что делать при конфликтной ситуации?",["Эскалировать по установленному порядку","Угрожать собеседнику","Провоцировать конфликт","Скрыть ситуацию"],0]
    ];
    for(let i=0;i<seed.rows.length;i++){
      for(let j=0;j<sample.length;j++){
        const q=sample[j];
        await pool.query("INSERT INTO questions(test_id,position,category,question_text,answers,correct_index,points) VALUES($1,$2,$3,$4,$5,$6,1)",
          [seed.rows[i].id,j+1,["ОБЩИЕ ЗНАНИЯ","СУБОРДИНАЦИЯ","ВНИМАТЕЛЬНОСТЬ"][i],q[0],JSON.stringify(q[1]),q[2]]);
      }
    }
  }
  // Existing installations are upgraded too: fill each standard test to ten questions without overwriting saved questions.
  const standardTests=await pool.query("SELECT id,title FROM tests WHERE title IN ('Переаттестация 1','Переаттестация 2','Переаттестация 3')");
  const defaults=[
    ["Что делать, если не уверен в ответе?",["Ответить наугад","Уточнить у ответственного","Игнорировать","Придумать правило"],1],
    ["Можно ли вмешиваться в чужую работу без согласования?",["Всегда можно","Нужно соблюдать порядок согласования","Можно тайно","По желанию"],1],
    ["Где проверять актуальные требования?",["В официальных инструкциях","В случайных сообщениях","Только по памяти","В догадках"],0],
    ["Как общаться с пользователем?",["Грубо","Спокойно и уважительно","Игнорировать","Оскорблять"],1],
    ["Что делать при ошибке в инструкции?",["Молча менять","Сообщить ответственному","Распространить слух","Ничего"],1],
    ["Можно ли передавать пароль?",["Да","Нет, пароль конфиденциален","Знакомому","В общий чат"],1],
    ["Что делать вне своих полномочий?",["Решать самовольно","Передать уполномоченному","Удалить обращение","Игнорировать"],1],
    ["Что сделать перед завершением обращения?",["Проверить результат и зафиксировать","Закрыть без проверки","Удалить историю","Ничего"],0],
    ["Как обращаться с внутренней информацией?",["Публиковать где угодно","Соблюдать конфиденциальность","Отправлять всем","Использовать лично"],1],
    ["Что делать при конфликте?",["Эскалировать по правилам","Угрожать","Провоцировать","Скрыть"],0]
  ];
  for(const test of standardTests.rows){
    const existing=await pool.query("SELECT COUNT(*)::int AS n FROM questions WHERE test_id=$1",[test.id]);
    for(let j=Number(existing.rows[0].n);j<10;j++){
      const q=defaults[j];
      await pool.query("INSERT INTO questions(test_id,position,category,question_text,answers,correct_index,points) VALUES($1,$2,'ОБЩИЕ ЗНАНИЯ',$3,$4,$5,1)",[test.id,j+1,q[0],JSON.stringify(q[1]),q[2]]);
    }
  }
}
app.get("/api/health",(req,res)=>res.json({ok:true}));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.post("/api/auth/register",authLimiter,asyncRoute(async(req,res)=>{
  const {username,email,password}=req.body||{};
  if(typeof username!=="string"||username.trim().length<2||username.trim().length>40)return res.status(400).json({error:"Никнейм должен содержать от 2 до 40 символов."});
  if(!validEmail(email))return res.status(400).json({error:"Укажите корректную почту."});
  if(!validPassword(password))return res.status(400).json({error:"Пароль должен содержать не менее 10 символов."});
  const hash=await bcrypt.hash(password,12);
  try{
    const r=await pool.query("INSERT INTO users(username,email,password_hash,role) VALUES($1,lower($2),$3,'participant') RETURNING id,username,email,role,active",
      [username.trim(),email.trim(),hash]);
    req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Не удалось создать сессию."});req.session.user=safeUser(r.rows[0]);res.json({user:req.session.user});});
  }catch(e){if(e.code==="23505")return res.status(409).json({error:"Такая почта или никнейм уже используются."});throw e;}
}));
app.post("/api/auth/login",authLimiter,asyncRoute(async(req,res)=>{
  const {identifier,email,password}=req.body||{};
  const login=String(identifier||email||"").trim();
  const r=await pool.query("SELECT * FROM users WHERE lower(email)=lower($1) OR lower(username)=lower($1) LIMIT 1",[login]);
  const u=r.rows[0];
  if(!u||!await bcrypt.compare(String(password||""),u.password_hash))return res.status(401).json({error:"Неверная почта или пароль."});
  if(!u.active)return res.status(403).json({error:"Аккаунт отключён. Обратитесь к администратору."});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Не удалось создать сессию."});req.session.user=safeUser(u);res.json({user:req.session.user});});
}));
app.post("/api/auth/logout",requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie("connect.sid");res.json({ok:true});}));
app.patch("/api/profile",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const username=String(req.body?.username||"").trim(), email=String(req.body?.email||"").trim().toLowerCase();
  if(username.length<2||username.length>40)return res.status(400).json({error:"Никнейм должен содержать от 2 до 40 символов."});
  if(!validEmail(email))return res.status(400).json({error:"Укажите корректную почту."});
  try {
    const r=await pool.query("UPDATE users SET username=$1,email=$2 WHERE id=$3 RETURNING id,username,email,role,active",[username,email,req.session.user.id]);
    req.session.user=safeUser(r.rows[0]);res.json({user:req.session.user});
  } catch(e){if(e.code==="23505")return res.status(409).json({error:"Этот никнейм или адрес почты уже заняты."});throw e;}
}));
app.get("/api/auth/discord", (req,res)=>{
  const clientId=process.env.DISCORD_CLIENT_ID, redirect=process.env.DISCORD_REDIRECT_URI;
  if(!clientId||!redirect)return res.status(503).send("Вход через Discord не настроен: добавьте DISCORD_CLIENT_ID и DISCORD_REDIRECT_URI.");
  const state=require("crypto").randomBytes(24).toString("hex");req.session.discordState=state;
  const url=new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id",clientId);url.searchParams.set("redirect_uri",redirect);
  url.searchParams.set("response_type","code");url.searchParams.set("scope","identify email");url.searchParams.set("state",state);
  res.redirect(url.toString());
});
app.get("/api/auth/discord/callback",asyncRoute(async(req,res)=>{
  const {code,state,error}=req.query;
  if(error||!code||!state||state!==req.session.discordState){delete req.session.discordState;return res.redirect("/?discord=error");}
  delete req.session.discordState;
  const clientId=process.env.DISCORD_CLIENT_ID, clientSecret=process.env.DISCORD_CLIENT_SECRET, redirect=process.env.DISCORD_REDIRECT_URI;
  if(!clientId||!clientSecret||!redirect)return res.redirect("/?discord=not-configured");
  const tokenResponse=await fetch("https://discord.com/api/oauth2/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:clientId,client_secret:clientSecret,grant_type:"authorization_code",code:String(code),redirect_uri:redirect})});
  const token=await tokenResponse.json();if(!tokenResponse.ok||!token.access_token)return res.redirect("/?discord=error");
  const profileResponse=await fetch("https://discord.com/api/users/@me",{headers:{Authorization:`Bearer ${token.access_token}`}});
  const profile=await profileResponse.json();if(!profileResponse.ok||!profile.id)return res.redirect("/?discord=error");
  let found=await pool.query("SELECT * FROM users WHERE discord_id=$1 OR (email IS NOT NULL AND lower(email)=lower($2)) LIMIT 1",[String(profile.id),String(profile.email||"")]);
  let u=found.rows[0];
  if(u){
    if(!u.discord_id)await pool.query("UPDATE users SET discord_id=$1 WHERE id=$2",[String(profile.id),u.id]);
  } else {
    if(!validEmail(profile.email))return res.redirect("/?discord=email-required");
    const baseName=String(profile.global_name||profile.username||"Discord").replace(/[^\p{L}\p{N}_ .-]/gu,"").trim().slice(0,32)||"Discord";
    let username=baseName, suffix=1;
    while((await pool.query("SELECT 1 FROM users WHERE lower(username)=lower($1)",[username])).rows.length) { username=(baseName.slice(0,32-String(suffix).length)+suffix++).slice(0,40); }
    const hash=await bcrypt.hash(require("crypto").randomBytes(32).toString("hex"),12);
    const created=await pool.query("INSERT INTO users(username,email,password_hash,discord_id) VALUES($1,lower($2),$3,$4) RETURNING *",[username,profile.email,hash,String(profile.id)]);u=created.rows[0];
  }
  if(!u.active)return res.redirect("/?discord=disabled");
  req.session.regenerate(err=>{if(err)return res.redirect("/?discord=error");req.session.user=safeUser(u);res.redirect("/");});
}));


app.get("/api/tests",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const r=await pool.query("SELECT t.id,t.title,t.description,COUNT(q.id)::int AS question_count FROM tests t LEFT JOIN questions q ON q.test_id=t.id WHERE t.active=true GROUP BY t.id ORDER BY t.created_at,t.id");
  res.json({tests:r.rows});
}));
app.get("/api/tests/random/choose",requireAuth,requireActive,asyncRoute(async(req,res)=>{
 const r=await pool.query("SELECT t.id FROM tests t JOIN questions q ON q.test_id=t.id WHERE t.active=true GROUP BY t.id HAVING COUNT(q.id)=10 ORDER BY random() LIMIT 1");
 if(!r.rows.length)return res.status(404).json({error:"Нет доступных переаттестаций с 10 вопросами."});
 res.json({testId:r.rows[0].id});
}));
app.get("/api/tests/:id",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const r=await pool.query("SELECT t.id,t.title,t.description,q.id AS question_id,q.position,q.category,q.question_text,q.answers,q.points FROM tests t JOIN questions q ON q.test_id=t.id WHERE t.id=$1 AND t.active=true ORDER BY q.position,q.id",[req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:"Тест не найден или в нём нет вопросов."});
  if(r.rows.length!==10)return res.status(409).json({error:"Переаттестация должна содержать ровно 10 вопросов. Обратитесь к администратору."});
  res.json({test:{id:r.rows[0].id,title:r.rows[0].title,description:r.rows[0].description,questions:r.rows.map(q=>({id:q.question_id,position:q.position,category:q.category,text:q.question_text,answers:q.answers,points:q.points}))}});
}));
app.post("/api/attempts",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const testId=Number(req.body?.testId);
  const t=await pool.query("SELECT id,title FROM tests WHERE id=$1 AND active=true",[testId]);
  if(!t.rows.length)return res.status(404).json({error:"Тест недоступен."});
  const qs=await pool.query("SELECT id,question_text,answers,correct_index,points FROM questions WHERE test_id=$1 ORDER BY position,id",[testId]);
  if(!qs.rows.length)return res.status(400).json({error:"В тесте пока нет вопросов."});
  const submitted=Array.isArray(req.body.answers)?req.body.answers:[];
  if(submitted.length!==qs.rows.length)return res.status(400).json({error:"Ответьте на все вопросы."});
  let score=0,maxScore=0,correctCount=0;
  const evaluated=qs.rows.map((q,i)=>{const selected=Number(submitted[i]);if(!Number.isInteger(selected)||selected<0||selected>=q.answers.length)throw Object.assign(new Error("Некорректный вариант ответа."),{status:400});const correct=selected===q.correct_index;const points=correct?Number(q.points):0;score+=points;maxScore+=Number(q.points);if(correct)correctCount++;return {q,selected,correct,points};});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const attempt=await client.query("INSERT INTO attempts(user_id,test_id,test_title,score,max_score,correct_count,question_count,status,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,'completed',NOW()) RETURNING id",
      [req.session.user.id,testId,t.rows[0].title,score,maxScore,correctCount,qs.rows.length]);
    for(const e of evaluated)await client.query("INSERT INTO attempt_answers(attempt_id,question_id,question_text,selected_index,correct_index,is_correct,points_awarded,max_points) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
      [attempt.rows[0].id,e.q.id,e.q.question_text,e.selected,e.q.correct_index,e.correct,e.points,e.q.points]);
    await client.query("COMMIT");
    res.json({attemptId:attempt.rows[0].id,score,maxScore,correctCount,questionCount:qs.rows.length});
  }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
}));
app.get("/api/results",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const isStaff=["admin","curator"].includes(req.session.user.role);
  const sql=isStaff
    ?"SELECT a.id,a.test_title,a.score,a.max_score,a.correct_count,a.question_count,a.status,a.curator_note,a.started_at,a.completed_at,a.reviewed_at,u.username,u.email FROM attempts a JOIN users u ON u.id=a.user_id ORDER BY a.started_at DESC LIMIT 500"
    :"SELECT a.id,a.test_title,a.score,a.max_score,a.correct_count,a.question_count,a.status,a.curator_note,a.started_at,a.completed_at,a.reviewed_at,u.username FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.user_id=$1 ORDER BY a.started_at DESC LIMIT 100";
  const r=await pool.query(sql,isStaff?[]:[req.session.user.id]);res.json({results:r.rows});
}));
app.get("/api/vyshka",requireAuth,requireActive,asyncRoute(async(req,res)=>{const r=await pool.query("SELECT id,title,details,position FROM vyshka_entries ORDER BY position,id");res.json({entries:r.rows});}));

// Admin/curator can maintain tests and review attempts; only admin can manage accounts and roles.
app.get("/api/staff/tests",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const t=await pool.query("SELECT id,title,description,active FROM tests ORDER BY id");
 const q=await pool.query("SELECT id,test_id,position,category,question_text,answers,correct_index,points FROM questions ORDER BY test_id,position,id");
 res.json({tests:t.rows.map(x=>({...x,questions:q.rows.filter(y=>String(y.test_id)===String(x.id))}))});
}));
app.post("/api/staff/tests",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const {title,description=""}=req.body||{};if(typeof title!=="string"||title.trim().length<2||title.length>120)return res.status(400).json({error:"Название должно содержать от 2 до 120 символов."});
 const r=await pool.query("INSERT INTO tests(title,description,created_by) VALUES($1,$2,$3) RETURNING id,title,description,active",[title.trim(),String(description).slice(0,2000),req.session.user.id]);res.status(201).json({test:r.rows[0]});
}));
app.put("/api/staff/tests/:id",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const {title,description,active}=req.body||{};if(typeof title!=="string"||title.trim().length<2)return res.status(400).json({error:"Укажите название теста."});
 const r=await pool.query("UPDATE tests SET title=$1,description=$2,active=$3,updated_at=NOW() WHERE id=$4 RETURNING id,title,description,active",[title.trim().slice(0,120),String(description||"").slice(0,2000),active!==false,req.params.id]);if(!r.rows.length)return res.status(404).json({error:"Тест не найден."});res.json({test:r.rows[0]});
}));
app.put("/api/staff/tests/:id/questions",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const id=Number(req.params.id),questions=req.body?.questions;
 if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Некорректная переаттестация."});
 if(!Array.isArray(questions)||questions.length!==10)return res.status(400).json({error:"В каждой переаттестации должно быть ровно 10 вопросов."});
 for(const q of questions){if(typeof q.text!=="string"||!q.text.trim()||!Array.isArray(q.answers)||q.answers.length<2||q.answers.length>8||q.answers.some(a=>typeof a!=="string"||!a.trim())||!Number.isInteger(Number(q.correctIndex))||Number(q.correctIndex)<0||Number(q.correctIndex)>=q.answers.length||!Number.isInteger(Number(q.points))||Number(q.points)<1||Number(q.points)>100)return res.status(400).json({error:"Проверьте текст вопроса, ответы, правильный вариант и баллы."});}
 const exists=await pool.query("SELECT id FROM tests WHERE id=$1",[id]);if(!exists.rows.length)return res.status(404).json({error:"Тест не найден."});
 const c=await pool.connect();try{
  await c.query("BEGIN");
  for(let i=0;i<questions.length;i++){
   const q=questions[i],values=[i+1,String(q.category||"ОБЩИЕ ЗНАНИЯ").slice(0,80),q.text.trim(),JSON.stringify(q.answers.map(a=>a.trim())),Number(q.correctIndex),Number(q.points)];
   if(q.id!==null&&q.id!==undefined&&String(q.id).trim()!==""){
    if(!/^\d+$/.test(String(q.id)))throw Object.assign(new Error("Не удалось определить существующий вопрос. Обновите страницу и попробуйте снова."),{status:400});
    const updated=await c.query("UPDATE questions SET position=$1,category=$2,question_text=$3,answers=$4::jsonb,correct_index=$5,points=$6 WHERE id=$7 AND test_id=$8 RETURNING id",[...values,String(q.id),id]);
    if(!updated.rows.length)throw Object.assign(new Error("Один из вопросов больше не существует в выбранной переаттестации. Обновите страницу."),{status:409});
   }else{
    await c.query("INSERT INTO questions(test_id,position,category,question_text,answers,correct_index,points) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)",[id,...values]);
   }
  }
  await c.query("COMMIT");res.json({ok:true,count:questions.length});
 }catch(e){await c.query("ROLLBACK");throw e;}finally{c.release();}
}));
app.post("/api/staff/vyshka/add",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const title=req.body?.title,details=req.body?.details||"";
 if(typeof title!=="string"||title.trim().length<2||title.trim().length>120)return res.status(400).json({error:"Название вышки должно содержать от 2 до 120 символов."});
 if(typeof details!=="string"||details.length>2000)return res.status(400).json({error:"Описание слишком длинное."});
 const position=await pool.query("SELECT COALESCE(MAX(position),0)+1 AS next_position FROM vyshka_entries");
 const r=await pool.query("INSERT INTO vyshka_entries(title,details,position,created_by) VALUES($1,$2,$3,$4) RETURNING id,title,details,position,created_at",[title.trim(),details.trim(),Number(position.rows[0].next_position),req.session.user.id]);
 res.status(201).json({entry:r.rows[0]});
}));
app.post("/api/staff/vyshka",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const entries=req.body?.entries;if(!Array.isArray(entries)||entries.length>300)return res.status(400).json({error:"Некорректный список."});
 const c=await pool.connect();try{await c.query("BEGIN");await c.query("DELETE FROM vyshka_entries");for(let i=0;i<entries.length;i++){const e=entries[i];if(typeof e.title!=="string"||!e.title.trim())continue;await c.query("INSERT INTO vyshka_entries(title,details,position,created_by) VALUES($1,$2,$3,$4)",[e.title.trim().slice(0,120),String(e.details||"").slice(0,2000),i,req.session.user.id]);}await c.query("COMMIT");res.json({ok:true});}catch(e){await c.query("ROLLBACK");throw e;}finally{c.release();}
}));
app.patch("/api/staff/attempts/:id",requireAuth,requireActive,requireStaff,asyncRoute(async(req,res)=>{
 const note=String(req.body?.note||"").slice(0,3000);const r=await pool.query("UPDATE attempts SET curator_note=$1,status='reviewed',reviewed_by=$2,reviewed_at=NOW() WHERE id=$3 RETURNING id",[note,req.session.user.id,req.params.id]);if(!r.rows.length)return res.status(404).json({error:"Результат не найден."});res.json({ok:true});
}));
app.get("/api/admin/users",requireAuth,requireActive,requireRole("admin"),asyncRoute(async(req,res)=>{
 const r=await pool.query("SELECT id,username,email,role,active,created_at FROM users ORDER BY created_at DESC LIMIT 1000");res.json({users:r.rows});
}));
app.patch("/api/admin/users/:id",requireAuth,requireActive,requireRole("admin"),asyncRoute(async(req,res)=>{
 const id=Number(req.params.id),{role,active}=req.body||{};if(!["participant","curator","admin"].includes(role)||typeof active!=="boolean")return res.status(400).json({error:"Некорректные права или статус."});
 if(id===Number(req.session.user.id)&&role!=="admin")return res.status(400).json({error:"Нельзя снять права администратора с собственной учётной записи."});
 if(role!=="admin"){const count=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin' AND active=true");const target=await pool.query("SELECT role,active FROM users WHERE id=$1",[id]);if(target.rows[0]?.role==="admin"&&target.rows[0]?.active&&Number(count.rows[0].n)<=1)return res.status(400).json({error:"Нельзя отключить или понизить последнего активного администратора."});}
 const r=await pool.query("UPDATE users SET role=$1,active=$2 WHERE id=$3 RETURNING id,username,email,role,active,created_at",[role,active,id]);if(!r.rows.length)return res.status(404).json({error:"Пользователь не найден."});res.json({user:r.rows[0]});
}));
app.use("/api", (err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(err.status||500).json({error:err.status?err.message:"Внутренняя ошибка сервера."});});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
init().then(()=>app.listen(process.env.PORT||3000,()=>console.log(`Pereattestacia app listening on ${process.env.PORT||3000}`))).catch(e=>{console.error("Startup failed:",e);process.exit(1);});
