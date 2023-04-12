import cpp

from FunctionCall fc, Function f
where
  f = fc.getTarget() and
  f.hasName("printf")
select fc 
