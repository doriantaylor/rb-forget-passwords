RSpec.describe ForgetPasswords do
  it "has a version number" do
    expect(ForgetPasswords::VERSION).not_to be nil
  end

  # this thing should test a bunch of stuff lol

  # one thing it should test is the template override

  # you can do that later lol

  # another thing we can do later is break out all these categories
  # into their own tests

  # TYPE TESTS

  # type coercions all work, great

  # STATE TESTS

  # database operations all work, great

  # both sqlite and postgres deployments work as expected

  # TEMPLATE TESTS

  # template substitutions and transformations all work, great

  # CLI TESTS

  # command-line tasks all work, great

  # APP TESTS (stand-alone)

  # all the endpoints that aren't the fastcgi authorizer look like
  # they work, great

  # (we can conceivably fire the app up in a harness and don't have to
  # have the whole schmozzle online)

  # we can furthermore use the auth bypass i just wrote to fake up sessions

  # SYSTEM TESTS

  # this is gonna be a bitch because it needs apache with
  # mod_authnz_fcgi configured *and* a working smtp server to run

  # (or does it? can we also just do this in a harness? i dunno)

  # fake up an smtp daemon? trap the inccoming message?

  # granted i think you could semi-automate it insofar as you only run
  # it under certain conditions

  # so you'd need something that fires up apache with a minimally
  # viable config

  # (again: do you really? pretty sure we can do a brain-in-a-vat setup)

end
