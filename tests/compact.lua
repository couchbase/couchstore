package.path = package.path .. ";tests/?.lua"
local testlib = require("testlib")

local function check_table(db, t)
   for i,v in ipairs(t) do
      local k = v[1]
      testlib.check_doc(db, k, v[2])
   end

   local found = 0
   db:changes(0, 0, function(di) found = found + 1 end)
   if found ~= #t then
      error("Expected " .. #t .. " results, found " .. found)
   end
end

function instuff(db, num, rev)
   local t = {}
   for i = 0, num, 1 do
      table.insert(t, {"k" .. i, "value " .. i, rev})
   end
   db:save_bulk(t)
end

function insdata(db)
   instuff(db, 50000, 1)
   instuff(db, 25000, 2)
   instuff(db, 100000, 3)
   instuff(db, 80000, 4)
   instuff(db, 75000, 5)
   db:save_local("_local/localtest", "Local doc")
   db:save_local("_local/localtest2", "Another local doc")
   db:commit()
end

function into_table(db)
   local t = {}
   db:changes(0, 0, function(di)
       table.insert(t, {di:id(), db:get_from_docinfo(di), di:rev()})
   end)
   return t
end

function compaction_test(dbname)
   local db = couch.open(dbname, true)
   outfile = os.tmpname()
   os.remove(outfile)
   insdata(db)
   local origdat = into_table(db)
   os.execute("./couch_compact " .. dbname .. " " .. outfile)
   local newdb = couch.open(outfile, false)
   check_table(newdb, origdat)
   testlib.check_local_doc(newdb, "_local/localtest", "Local doc")
   testlib.check_local_doc(newdb, "_local/localtest2", "Another local doc")
   db:close()
   newdb:close()
end

testlib.run_test("Compaction test", compaction_test)
os.remove(outfile)
return testlib.fail_count()
