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
      ["Где проверять актуальные требования к работе?",["В актуальных официальных инструкциях","В случайных сообщениях","Только по памяти","В догадках"],0]
    ];
    for(let i=0;i<seed.rows.length;i++){
      const q=sample[i];
      await pool.query("INSERT INTO questions(test_id,position,category,question_text,answers,correct_index,points) VALUES($1,1,$2,$3,$4,$5,1)",
        [seed.rows[i].id,["ОБЩИЕ ЗНАНИЯ","СУБОРДИНАЦИЯ","ВНИМАТЕЛЬНОСТЬ"][i],q[0],JSON.stringify(q[1]),q[2]]);
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
  }catch(e){if(e.code==="23505")return res.status(409).json({error:"Аккаунт с такой почтой уже существует."});throw e;}
}));
app.post("/api/auth/login",authLimiter,asyncRoute(async(req,res)=>{
  const {email,password}=req.body||{};
  const r=await pool.query("SELECT * FROM users WHERE email=lower($1)",[String(email||"").trim()]);
  const u=r.rows[0];
  if(!u||!await bcrypt.compare(String(password||""),u.password_hash))return res.status(401).json({error:"Неверная почта или пароль."});
  if(!u.active)return res.status(403).json({error:"Аккаунт отключён. Обратитесь к администратору."});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Не удалось создать сессию."});req.session.user=safeUser(u);res.json({user:req.session.user});});
}));
app.post("/api/auth/logout",requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie("connect.sid");res.json({ok:true});}));

app.get("/api/tests",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const r=await pool.query("SELECT t.id,t.title,t.description,COUNT(q.id)::int AS question_count FROM tests t LEFT JOIN questions q ON q.test_id=t.id WHERE t.active=true GROUP BY t.id ORDER BY t.created_at,t.id");
  res.json({tests:r.rows});
}));
app.get("/api/tests/:id",requireAuth,requireActive,asyncRoute(async(req,res)=>{
  const r=await pool.query("SELECT t.id,t.title,t.description,q.id AS question_id,q.position,q.category,q.question_text,q.answers,q.points FROM tests t JOIN questions q ON q.test_id=t.id WHERE t.id=$1 AND t.active=true ORDER BY q.position,q.id",[req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:"Тест не найден или в нём нет вопросов."});
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
 if(!Array.isArray(questions)||questions.length>250)return res.status(400).json({error:"Некорректный список вопросов."});
 for(const q of questions){if(typeof q.text!=="string"||!q.text.trim()||!Array.isArray(q.answers)||q.answers.length<2||q.answers.length>8||q.answers.some(a=>typeof a!=="string"||!a.trim())||!Number.isInteger(Number(q.correctIndex))||Number(q.correctIndex)<0||Number(q.correctIndex)>=q.answers.length||!Number.isInteger(Number(q.points))||Number(q.points)<1||Number(q.points)>100)return res.status(400).json({error:"Проверьте текст вопроса, ответы, правильный вариант и баллы."});}
 const exists=await pool.query("SELECT id FROM tests WHERE id=$1",[id]);if(!exists.rows.length)return res.status(404).json({error:"Тест не найден."});
 const c=await pool.connect();try{await c.query("BEGIN");await c.query("DELETE FROM questions WHERE test_id=$1",[id]);for(let i=0;i<questions.length;i++){const q=questions[i];await c.query("INSERT INTO questions(test_id,position,category,question_text,answers,correct_index,points) VALUES($1,$2,$3,$4,$5,$6,$7)",[id,i+1,String(q.category||"ОБЩИЕ ЗНАНИЯ").slice(0,80),q.text.trim(),JSON.stringify(q.answers.map(a=>a.trim())),Number(q.correctIndex),Number(q.points)]);}await c.query("COMMIT");res.json({ok:true,count:questions.length});}catch(e){await c.query("ROLLBACK");throw e;}finally{c.release();}
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
