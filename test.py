import openai
from agente import motor_openai as m
try:
    r = m.cliente().chat.completions.create(model=m.MODELO, messages=[{"role": "user", "content": "di hola"}])
    print("OK:", r.choices[0].message.content)
except openai.APIStatusError as e:
    print("ERROR", e.status_code, e.response.text[:500])
