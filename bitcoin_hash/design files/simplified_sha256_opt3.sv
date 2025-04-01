module simplified_sha256_opt3 #(parameter integer NUM_OF_WORDS = 4)(
 input logic  clk, reset_n, start,
 //input logic  [15:0] message_addr, output_addr,
 input logic [255:0] hash_value,//from phase 1
 input logic [127:0] message_blocks, //4 message blocks
 input logic [3:0] nonce, //nonce value, from 0 to 15
 output logic valid, /*mem_clk, mem_we,*/ //mem_we : 1 = write, 0 = read
 output logic [31:0] hash_nonce //hash value of phase 3 corresponding to the nonce value
 //output logic [15:0] mem_addr,
 //output logic [31:0] mem_write_data,
 /*input logic [31:0] mem_read_data*/);

// FSM state variables 
enum logic [1:0] {IDLE, /*READ,*/ BLOCK, COMPUTE/*, WRITE*/} state;
//localparam k = NUM_OF_WORDS * 32; //total bits
//localparam padz = 448 + ((1 + ))

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
//logic [31:0] w[64]; //64 message schedules
logic [31:0] wt[16]; //only store the most recent 16 message schedules
//logic [31:0] message[20]; //20 words
//logic [31:0] message[4]; //4 words
//logic [31:0] wt;  //one message schedule
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7; //hash value for each block
logic [31:0] a, b, c, d, e, f, g, h; //
//logic [ 7:0] /*i,*/ j, p, t;
logic [6:0] t;
logic [1:0] j;

//logic [15:0] offset; // in word address
//logic [ 7:0] num_blocks;
//logic        cur_we;
//logic [15:0] cur_addr;
//logic [31:0] cur_write_data;
//logic [512:0] memory_block;
//logic [31:0] hash_nonce_reg;
//logic [ 7:0] tstep;
//int l;
logic [31:0] message_nonce;
//logic [31:0] w_k_d;
logic [31:0] Pt;

logic [1:0] cnt;
//logic [31:0] Qt;

/*logic [31:0] h0_p; //16 h0 of phase 2
logic [31:0] h1_p;
logic [31:0] h2_p;
logic [31:0] h3_p;
logic [31:0] h4_p;
logic [31:0] h5_p;
logic [31:0] h6_p;
logic [31:0] h7_p;*/

//logic [31:0] sigma0;//sigma for word expansion
//logic [31:0] sigma1;//sigma for word expansion

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


//assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
//assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation
   determine_num_blocks = (size / 16) + 1;
	
endfunction


// SHA256 hash round
/*function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + k[t] + w;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction*/

/*function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w_k
                                 );
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + w_k;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction*/

function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, Pt
                                 );
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = S1 + ch + Pt;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	 end
endfunction

/*function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, Pt, Qt
                                 );
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 // Student to add remaning code below
		 // Refer to SHA256 discussion slides to get logic for this function
		 ch = (e & f) ^ ((~e) & g);
		 t1 = S1 + ch;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj + Pt;
		 sha256_op = {t1 + t2, a, b, c, t1 + Qt, e, f, g};
	 end
endfunction*/

function logic [31:0] wtnew;  // function with no inputs
	begin
		logic [31:0] s0, s1;
		s0 = rightrotate(wt[1],7)^rightrotate(wt[1],18)^(wt[1]>>3);
		s1 = rightrotate(wt[14],17)^rightrotate(wt[14],19)^(wt[14]>>10);
		wtnew = wt[0] + s0 + wt[9] + s1;
	end
endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
//assign mem_clk = clk;
//assign mem_addr = cur_addr + offset;
//assign mem_we = cur_we;
//assign mem_write_data = cur_write_data;

//assign hash_nonce = hash_nonce_reg;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


assign message_nonce = /*message_blocks[127:96] +*/ nonce;


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    //cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
       // Student to add rest of the code  
		   
			h0 <= hash_value[31:0];
			h1 <= hash_value[63:32];
			h2 <= hash_value[95:64];
			h3 <= hash_value[127:96];
			h4 <= hash_value[159:128];
			h5 <= hash_value[191:160];
			h6 <= hash_value[223:192];
			h7 <= hash_value[255:224];
			
			
			//cur_we <= 1'b0; //read
			//cur_addr <= message_addr;
			//offset <= 16'h0000;
			//i <= 0; //index for 64 rounds of word expansion and SHA256 operation
			j <= 1; //first block
			
			
			//state <= READ;
			state <= BLOCK;

       end
    end
	 

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
	 /*READ : begin
			
			
			message[0] <= message_blocks[31:0];
			message[1] <= message_blocks[63:32];
			message[2] <= message_blocks[95:64];
			message[3] <= message_blocks[127:96] + nonce; //word contain nonce
			state <= BLOCK;
	 end*/
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation, do block pre-process
		//i <= 0;	
		t <= 0;
		if (j < /*num_blocks*/2 + 1) begin
         if (j == 1) begin //do second phase
				cnt <= 0;
				//memory_block <= {32'd640,{10{32'h00000000}},32'h80000000,message_nonce, message_blocks[95:64], message_blocks[63:32], message_blocks[31:0]};
				{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};//result from first phase
				//{h,g,f,e,d,c,b,a} <= hash_value;
				//j <= j + 1;
				state <= COMPUTE;
			end
			else begin //do third phase				
				
				cnt <= 1;
				//memory_block <= {32'd256, {6{32'h00000000}}, 32'h80000000, h7, h6, h5, h4, h3, 
				//					  h2, h1, h0}; //result from the second phase
				{a,b,c,d,e,f,g,h} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f,
														 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19}; 								  
				//{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};
				//j <= j + 1;
				state <= COMPUTE;
			end
			
		end
		else begin
			//state <= WRITE;
			hash_nonce <= h0;
			state <= IDLE;
			j <= 1;
			cnt <= 0;
		end   
    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block
		  //word expansion
		  if (t < 64) begin
			  if (t < 16) begin
						//wt[t] <= memory_block[32*(t+1)-1 -: 32];
						if (cnt == 0) begin //first block
							
							case(t)
								0 : wt[0] <= message_blocks[31:0];
								1 : wt[1] <= message_blocks[63:32];
								2 : wt[2] <= message_blocks[95:64];
								3 : wt[3] <= message_nonce;
								default : {wt[15],wt[14],wt[13],wt[12],wt[11],wt[10],wt[9],wt[8],wt[7],wt[6],wt[5],wt[4]} <= 
							{32'd640,{10{32'h00000000}},32'h80000000};
								/*4 : wt[4] <= 32'h80000000;
								5 : wt[5] <= 32'h00000000;
								6 : wt[6] <= 32'h00000000;
								7 : wt[7] <= 32'h00000000;
								8 : wt[8] <= 32'h00000000;
								9 : wt[9] <= 32'h00000000;
								10 : wt[10] <= 32'h00000000;
								11 : wt[11] <= 32'h00000000;
								12 : wt[12] <= 32'h00000000;
								13 : wt[13] <= 32'h00000000;
								14 : wt[14] <= 32'h00000000;
								15 : wt[15] <= 32'd640;*/
							endcase
						end
						else if (cnt == 1) begin //second block
							
							case (t)
								0 : wt[0] <= h0;
								1 : wt[1] <= h1;
								2 : wt[2] <= h2;
								3 : wt[3] <= h3;
								4 : wt[4] <= h4;
								5 : wt[5] <= h5;
								6 : wt[6] <= h6;
								7 : wt[7] <= h7;
								default : {wt[15],wt[14],wt[13],wt[12],wt[11],wt[10],wt[9],wt[8]} <= 
								 {32'd256, {6{32'h00000000}}, 32'h80000000};
								/*8 : wt[8] <= 32'h80000000;
								9 : wt[9] <= 32'h00000000;
								10 : wt[10] <= 32'h00000000;
								11 : wt[11] <= 32'h00000000;
								12 : wt[12] <= 32'h00000000;
								13 : wt[13] <= 32'h00000000;
								14 : wt[14] <= 32'h00000000;
								15 : wt[15] <= 32'd256;*/
							endcase
						end
						
						if (t > 1) begin
							Pt <= wt[t-1] + k[t-1] + g;
							//Qt <= wt[t-1] + k[t-1] + g + c;
							{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,Pt);
							//w_k_d <= wt[t-1] + k[t-1];							
						end
						else begin
							//w_k_d <= wt[t-1] + k[t-1];
							Pt <= wt[0] + k[0] + h;
							//Qt <= wt[t-1] + k[t-1] + h + d;
						end
						
				end		
				else begin
					Pt <= wt[15] + k[t-1] + g;
					//Qt <= wt[15] + k[t-1] + g + c;
					{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,Pt);
					for (int n = 0; n < 15; n++) wt[n] <= wt[n+1]; // just wires
					wt[15] <= wtnew();
					
					
					
						
				end
				
				t <= t + 1;
				state <= COMPUTE;
			end
			else if (t == 64) begin //SHA256 operation
					
					
					Pt <= wt[15] + k[t-1] + g;
					//Qt <= wt[15] + k[t-1] + g + c;
					{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,Pt);
					t <= t + 1;
					state <= COMPUTE;
				
			end		
			else if (t == 65) begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a,b,c,d,e,f,g,Pt);
				t <= t + 1;
				state <= COMPUTE;
			end
			else begin
			  if (j == 1) begin //second phase complete
				  
				  h0 <= h0 + a;
				  h1 <= h1 + b;
				  h2 <= h2 + c;
				  h3 <= h3 + d;
				  h4 <= h4 + e;
				  h5 <= h5 + f;
				  h6 <= h6 + g;
				  h7 <= h7 + h;
				  /*h0 <= hash_value[31:0] + a;
				  h1 <= hash_value[63:32] + b;
				  h2 <= hash_value[95:64] + c;
				  h3 <= hash_value[127:96] + d;
				  h4 <= hash_value[159:128] + e;
				  h5 <= hash_value[191:160] + f;
				  h6 <= hash_value[223:192] + g;
				  h7 <= hash_value[255:224] + h;*/
				  j <= j + 1;
				  state <= BLOCK;
			  end
			  else begin //third phase complete
				
				  h0 <= 32'h6a09e667 + a;
				 /* h1 <= 32'hbb67ae85 + b;
				  h2 <= 32'h3c6ef372 + c;
				  h3 <= 32'ha54ff53a + d;
				  h4 <= 32'h510e527f + e;
				  h5 <= 32'h9b05688c + f;
				  h6 <= 32'h1f83d9ab + g;
				  h7 <= 32'h5be0cd19 + h;*/
				  j <= j + 1;
				  state <= BLOCK;
			  end
			  
			end
			
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    /*WRITE: begin
		
		hash_nonce <= h0;
		state <= IDLE;
		
			
    end*/
   default : begin
		state <= IDLE;
	end
	endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign valid = (state == IDLE);

endmodule
