package.path = package.path .. ";tests/?.lua"
local testlib = require("testlib")

function simpletrunc(dbname)
   local db = couch.open(dbname, true)
   db:save("k", "original value", 1)
   db:commit()

   testlib.check_doc(db, "k", "original value")

   db:save("k", "second value", 1)
   db:commit()

   testlib.check_doc(db, "k", "second value")

   db:truncate(-10)
   db:close()

   db = couch.open(dbname, false, true)
   testlib.check_doc(db, "k", "original value")

   db:save("k", "third value", 1)
   db:commit()
   db:close()

   db = couch.open(dbname)
   testlib.check_doc(db, "k", "third value")
end

function do_mangle(dbname, offset)
   local db = couch.open(dbname, true)
   db:save("k", "original value", 1)
   db:commit()

   testlib.check_doc(db, "k", "original value")

   db:save("k", "second value", 1)
   db:commit()

   testlib.check_doc(db, "k", "second value")

   db:close()

   local f = io.open(dbname, "r+")
   local corruptWith = "here be some garbage"
   local treelen = f:seek("end") % 4096
   if offset > treelen then
      return false
   end
   f:seek("end", 0 - treelen)
   f:write(corruptWith)
   f:close()

   db = couch.open(dbname, false, true)
   testlib.check_doc(db, "k", "original value")

   db:save("k", "third value", 1)
   db:commit()
   db:close()

   db = couch.open(dbname)
   testlib.check_doc(db, "k", "third value")
   return true
end

-- Mangle the header with some arbitrary data from the beginning of
-- the header boundary to the end.  The header is located by the EOF %
-- 4096.  Should probably do something special when EOF *is* at a 4k
-- boundary, but this test is valuable without it.
function header_mangling(dbname)
   local i = 0
   while do_mangle(dbname, i) do
      i = i + 1
      os.remove(dbname)
   end
end

testlib.run_test("Simple truncation test", simpletrunc)
testlib.run_test("Various mangling of headers", header_mangling)
return testlib.fail_count()
