/////////////////////////////////////////////////////////////////////////
// 0L Module
// TestFixtures
// Collection of vdf proofs for testing.
/////////////////////////////////////////////////////////////////////////

address 0x1 {
module TestFixtures{
  use 0x1::Testnet;
    public fun easy_difficulty(): u64 {
      100
    }

    public fun hard_difficulty(): u64 {
      120000000
    }

    public fun security(): u64 {
      512
    }



    public fun easy_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"aa"
    }

    public fun easy_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"0051dfa4c3341c18197b72f5e5eecc693eb56d408206c206d90f5ec7a75f833b2affb0ea7280d4513ab8351f39362d362203ff3e41882309e7900f470f0a27eeeb7b"
    }

    //FROM: diem/fixtures/block_0.json.stage.alice
    public fun alice_0_easy_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"87515d94a244235a1433d7117bc0cb154c613c2f4b1e67ca8d98a542ee3f59f5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006578706572696d656e74616c6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000074657374"
    }

    public fun alice_0_easy_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"00639237baac2348608e1e6dbcee015a2a628780d97f865f17c6e9f99d325ecb120052b0be3b0578af20cf0c4304ab14cbe7635a4247ed4ff3fcbd488bc66eb88cb7"
    }

        //FROM: diem/fixtures/block_1.json.stage.alice

    public fun alice_1_easy_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }

    public fun alice_1_easy_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }

    public fun alice_0_hard_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"87515d94a244235a1433d7117bc0cb154c613c2f4b1e67ca8d98a542ee3f59f5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006578706572696d656e74616c000e270700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000074657374"
    }

    public fun alice_0_hard_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"003129757ba5d9ae121b7121cce3886a6dbe03189e6f13d5bddda8d4efa05244bafff51c533931e87f9f5902b3d9d0530d1d193319bac93e8a347a5e4691ea41bca7003fd3933f6fcfc699b5342df9f5620748150a2b656a11970823bae3e3e3bd828800170568ffb788062eb6c48efff5403e4b71818d9be7ed306daba666a1efeef233007015c055b14ae3dc8255634fb10e1f1d70b5d70fba13ccbaac5fd44f8218739ffff6b3c45069c57047c55aab08b4c61a8386b7aeaf62bd125098f407e9cc40fbbb003fda3202ea6a23bb14b2e3d498b1d2954f4d74766d7fc20ab51490fe601e6ece0004c73b6c3b35f6ba763ccbe04730fdd9a862cc3202878cfd8fdf7b89eb0548ab0069d4b6cf75ec331e722cf360ad2cecd43feffb7a4a566f5bdd33504398683944ffcec3d3ba5ec381df20f53b0766ee2e80a19fa3495095730207da2704cae9081b00524fa4d81b313287b35cefe80a3ebbe5fc529e1b6a0013813f92d9187e505f4cffda75506314a5df9aeb7af8a89e574b9382f22641271060a67e3424b2da535265006760fc5ac60656da47d0363774295cb96ce104a575fdd7656f48f6fa4804d780005a982cd19e1d8684fc04d61a6bdf39b04d41daba0c0cb3910a8607e6a9822f030027cf3982dbfaeaa7976c2fccb4604b898faec5c061522ca8ba10a973c8207a9e0017725e9d198c3ca17ef8e764c1553fe0b82ecc10c3f5ae5afbe06f2dc98af0390021fe6016d722bc196ef1dbf2a2c2655a756ec8956baf7f36e458fcbcc7c33ac10002f2ff2c34faf58a9137a7544b9ea67f8bd46a9380cf968dae0a6b520c6f8e1900165626a99817d15ed7235e037d373b2d335d4918ea6f628f216e2afafc451e55ffea1c723cb35dcc9d6c8c2052e4d2ff7e98ba64dcf678fc7aa543cc1a36b4b4670065adbdc6d107396bdf798f6403eaead853d493a29eaed4477f00adc67d33f800ffcc430ba294d63a3ab3e76e89004fd258a140c62074071cec295bdde892f71dfd0000b109e1e6caca6b8ca5a6f29bb7731dd8399d332fe892145e3f9a53fb076364000053a90d74dcf7a5d7a02784618e5c04b5b32edeeaf51ee7536d6feeb80f8fb5000ca74399c6c9cb8f17467c58d14098b85364720c2006e7819ee01c0019b66fc6fff889fd65ece66541d964a4a2b7d1acc18506c1aed659bcbccae5a02889f3655500269b2870f2f0aa3ab83a84a238e759172d4eed3988ab31d1b6aaccaae3481824000ff824b85e530b72abd8ac61e2f72162f9d59987e31309b503f54be6ab30f8f3003587ff53b97702151c9be7e8c85df9bdfea72a64405200daf1ab59757791f625ffdde7558e610cb616691090e4cac756dbbc0759998db39627b5053a6dfe0a933f003c6b58a7f8a849a13592b3ec8f64299fefe6984b51b25e2b2efa4ea1c32bb2c8ffcb630cc5c4ff706a3ad7f41f381f062433d9b45a6c59682c62ae4792e6619b4d000c040c280d43cec214e3448f04ed4425c51990120e91b229bf0cfb1edf1e2d96fff47c52162a4a91cb4a16691d7d67ded579bdd92b2dee8a2663e07bf4f95bd8af00168f9c55b1e1c8d19aa8ca8fc1fdd425ba83daf564ba6615bf42d3ac627db87cfff80b67424ce7f6fbdd8f8e1c6e692330ad2f1a7214956c75b6414286478929a5000dd8b369ed21817704bff2824165337910cbe468ff4c684b02dc7d5757de1460000d376a2a9517885fcb49c5b51b689cde63d73616e85a15afad2d4d53ec4f93fd005c0c4c4da1929a6b18459e19f6d0a14f613fed755d19b532ad6d088cd3ecd4c20039b3f8a0e06ca7328a06366ea495e9c6a565eaa0cec60f827d786410977bf511001f3eb458785831eed0d4f2184ff7021b70eacc1c6999a65e487a05b0723f212700197916ee957f87e21854d38710dccefbf670265d81365000d47605f5c00bac0d"
    }
    public fun alice_1_hard_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }

    public fun alice_1_hard_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }

    public fun eve_0_easy_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"2bffcbd0e9016013cb8ca78459f69d2b3dc18d1cf61faac6ac70e3a63f062e4b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006578706572696d656e74616c6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000074657374"
    }

    public fun eve_0_easy_sol(): vector<u8>  {
      assert(Testnet::is_testnet(), 130102014010);
      x"003669fb011987c2cb247a14ee6a3a3139ac52299c63d341148a931c5081e1791e002b80a19d4e4771c3f979f124aaf94cc020e6b8e3e36ae1c83b007fc8c6374ed3"
    }

    public fun eve_1_easy_chal(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }

    public fun eve_1_easy_sol(): vector<u8> {
      assert(Testnet::is_testnet(), 130102014010);
      x"a0a0"
    }
  }
}
