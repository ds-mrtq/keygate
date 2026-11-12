-- KeyGate smoke: chứng minh đăng nhập được bằng wallet tạm, không có mật khẩu trong lệnh.
set heading on feedback off pagesize 50 linesize 200
select user as db_user,
       sys_context('USERENV', 'DB_NAME') as db_name,
       to_char(sysdate, 'YYYY-MM-DD HH24:MI:SS') as now_db
from dual;
